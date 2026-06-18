package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	vpnDirectHandshakeTimeout = 10 * time.Second
	vpnDirectDialTimeout      = 8 * time.Second
	vpnDirectMaxFrameSize     = 4 << 20
	vpnDirectMaxWireFrameSize = vpnDirectMaxFrameSize + chacha20poly1305.Overhead
	vpnDirectV2Version        = 2
	vpnDirectV2ClockSkew      = 2 * time.Minute
	vpnDirectDefaultWSPath    = "/agent-vpn/ws"
)

var defaultAgentVPNDirectManager = NewAgentVPNDirectManager()

type AgentVPNDirectManager struct {
	mu           sync.Mutex
	listener     net.Listener
	cert         tls.Certificate
	certSHA      string
	sessions     map[string]*vpnDirectPendingStream
	replayNonces map[string]time.Time
}

type vpnDirectHandshake struct {
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
}

type vpnDirectHandshakeResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type vpnDirectV2Hello struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Transport string `json:"transport"`
	Crypto    string `json:"crypto"`
	MAC       string `json:"mac"`
}

type vpnDirectV2Accept struct {
	Version    int    `json:"version"`
	SessionID  string `json:"session_id"`
	EntryNonce string `json:"entry_nonce"`
	ExitNonce  string `json:"exit_nonce"`
	Timestamp  int64  `json:"timestamp"`
	Transport  string `json:"transport"`
	Crypto     string `json:"crypto"`
	MAC        string `json:"mac"`
}

func NewAgentVPNDirectManager() *AgentVPNDirectManager {
	return &AgentVPNDirectManager{
		sessions:     map[string]*vpnDirectPendingStream{},
		replayNonces: map[string]time.Time{},
	}
}

func initAgentVPNDirect() {
	if defaultAgentVPNDirectManager == nil {
		return
	}
	if err := defaultAgentVPNDirectManager.Start(&agentConfig); err != nil {
		printf("Agent VPN direct relay disabled: %v", err)
		agentConfig.VPNDirectEnabled = false
		agentConfig.VPNDirectListenPort = 0
		agentConfig.VPNDirectCertSHA256 = ""
	}
}

func (m *AgentVPNDirectManager) Start(cfg *model.AgentConfig) error {
	if cfg == nil || cfg.DisableVPN || !cfg.VPNDirectEnabled {
		return nil
	}
	listenAddr := strings.TrimSpace(cfg.VPNDirectListen)
	if listenAddr == "" {
		listenAddr = ":8090"
	}
	cert, certSHA, err := loadOrCreateVPNDirectCertificate(defaultVPNDirectCertPath(), defaultVPNDirectKeyPath())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	port, err := listenerPort(ln)
	if err != nil {
		_ = ln.Close()
		return err
	}

	m.mu.Lock()
	if m.listener != nil {
		_ = ln.Close()
		cfg.VPNDirectListenPort = uint32(port)
		cfg.VPNDirectCertSHA256 = m.certSHA
		m.mu.Unlock()
		return nil
	}
	m.listener = ln
	m.cert = cert
	m.certSHA = certSHA
	m.mu.Unlock()

	cfg.VPNDirectListen = listenAddr
	cfg.VPNDirectListenPort = uint32(port)
	cfg.VPNDirectCertSHA256 = certSHA
	go m.acceptLoop(ln)
	printf("Agent VPN direct relay listening on %s (transports=%s,%s crypto=%s)", ln.Addr().String(), model.VPNDirectTransportTCPTLS, model.VPNDirectTransportWSTLS, model.VPNDirectCryptoV2)
	return nil
}

func (m *AgentVPNDirectManager) Register(req model.VPNControlRequest) (vpnIOStream, error) {
	if strings.TrimSpace(req.SessionID) == "" {
		return nil, errors.New("session_id is required")
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, errors.New("token is required")
	}
	if req.ExpiresAtUnix <= 0 {
		return nil, errors.New("expires_at is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener == nil {
		return nil, errors.New("VPN direct relay listener is not running")
	}
	if _, exists := m.sessions[req.SessionID]; exists {
		return nil, fmt.Errorf("VPN direct session %s already registered", req.SessionID)
	}
	stream := newVPNDirectPendingStream(m, req)
	m.sessions[req.SessionID] = stream
	return stream, nil
}

func (m *AgentVPNDirectManager) Dial(ctx context.Context, req model.VPNControlRequest) (vpnIOStream, error) {
	switch normalizeVPNDirectTransport(req.Extra["direct_transport"]) {
	case model.VPNDirectTransportWSTLS:
		return m.dialWSTLS(ctx, req)
	default:
		return m.dialTCPTLS(ctx, req)
	}
}

func (m *AgentVPNDirectManager) dialTCPTLS(ctx context.Context, req model.VPNControlRequest) (vpnIOStream, error) {
	address := strings.TrimSpace(req.Extra["direct_address"])
	if address == "" {
		return nil, errors.New("direct_address is required")
	}
	certSHA := normalizeVPNDirectSHA256(req.Extra["direct_cert_sha256"])
	if certSHA == "" {
		return nil, errors.New("direct_cert_sha256 is required")
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, errors.New("token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{Timeout: vpnDirectDialTimeout}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing VPN direct peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != certSHA {
				return errors.New("VPN direct peer certificate fingerprint mismatch")
			}
			return nil
		},
	}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := writeVPNDirectJSON(conn, vpnDirectHandshake{SessionID: req.SessionID, Token: token}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var response vpnDirectHandshakeResponse
	if err := readVPNDirectJSON(conn, &response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !response.OK {
		_ = conn.Close()
		if response.Error == "" {
			response.Error = "VPN direct handshake rejected"
		}
		return nil, errors.New(response.Error)
	}
	return &vpnDirectConnStream{conn: conn}, nil
}

func (m *AgentVPNDirectManager) dialWSTLS(ctx context.Context, req model.VPNControlRequest) (vpnIOStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	address := strings.TrimSpace(req.Extra["direct_address"])
	if address == "" {
		return nil, errors.New("direct_address is required")
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, errors.New("token is required")
	}
	wsURL, serverName := vpnDirectWSURL(req)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	if !vpnDirectTLSVerifyEnabled(req.Extra["direct_tls_verify"]) {
		tlsConfig.InsecureSkipVerify = true
	}
	certSHA := normalizeVPNDirectSHA256(req.Extra["direct_cert_sha256"])
	if tlsConfig.InsecureSkipVerify && certSHA == "" {
		return nil, errors.New("direct_cert_sha256 is required when direct_tls_verify is disabled")
	}
	if certSHA != "" {
		tlsConfig.VerifyPeerCertificate = vpnDirectPeerCertificateVerifier(certSHA)
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: vpnDirectDialTimeout,
		NetDialContext: (&net.Dialer{
			Timeout: vpnDirectDialTimeout,
		}).DialContext,
		TLSClientConfig: tlsConfig,
	}
	conn, response, err := dialer.DialContext(ctx, wsURL, http.Header{})
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("VPN direct websocket dial failed: %w (status=%s)", err, response.Status)
		}
		return nil, err
	}
	helloNonce, err := vpnDirectRandomHex(16)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	hello := vpnDirectV2Hello{
		Version:   vpnDirectV2Version,
		SessionID: strings.TrimSpace(req.SessionID),
		Timestamp: time.Now().Unix(),
		Nonce:     helloNonce,
		Transport: model.VPNDirectTransportWSTLS,
		Crypto:    model.VPNDirectCryptoV2,
	}
	hello.MAC = vpnDirectV2HelloMAC(token, hello)
	if err := writeVPNDirectEncryptedControlFrame(conn, token, hello.SessionID, req.Extra["direct_ws_path"], "hello", hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var accept vpnDirectV2Accept
	if err := readVPNDirectEncryptedControlFrame(conn, token, hello.SessionID, req.Extra["direct_ws_path"], "accept", &accept); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := validateVPNDirectV2Accept(token, hello, accept); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stream, err := newVPNDirectSecureStream(&vpnDirectWebSocketStream{conn: conn}, req.SessionID, token, hello.Nonce, accept.ExitNonce, true)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stream, nil
}

func (m *AgentVPNDirectManager) unregister(sessionID string, stream *vpnDirectPendingStream) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current := m.sessions[sessionID]; current == stream {
		delete(m.sessions, sessionID)
	}
}

func (m *AgentVPNDirectManager) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go m.handleConn(conn)
	}
}

func (m *AgentVPNDirectManager) handleConn(raw net.Conn) {
	br := bufio.NewReader(raw)
	first, err := br.Peek(1)
	if err != nil {
		_ = raw.Close()
		return
	}
	if len(first) > 0 && (first[0] == 'G' || first[0] == 'P' || first[0] == 'H' || first[0] == 'O') {
		m.handleHTTPConn(raw, br)
		return
	}
	m.handleLegacyTLSConn(&vpnDirectBufferedConn{Conn: raw, reader: br})
}

func (m *AgentVPNDirectManager) handleLegacyTLSConn(raw net.Conn) {
	m.mu.Lock()
	cert := m.cert
	m.mu.Unlock()
	conn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	_ = conn.SetDeadline(time.Now().Add(vpnDirectHandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}
	buffered := &vpnDirectBufferedConn{Conn: conn, reader: br}
	if len(first) > 0 && (first[0] == 'G' || first[0] == 'P' || first[0] == 'H' || first[0] == 'O') {
		_ = conn.SetDeadline(time.Time{})
		m.handleHTTPConn(buffered, br)
		return
	}
	var handshake vpnDirectHandshake
	if err := readVPNDirectJSON(buffered, &handshake); err != nil {
		_ = conn.Close()
		return
	}
	stream, err := m.consumeSession(handshake.SessionID, handshake.Token)
	if err != nil {
		_ = writeVPNDirectJSON(buffered, vpnDirectHandshakeResponse{OK: false, Error: err.Error()})
		_ = conn.Close()
		return
	}
	if err := writeVPNDirectJSON(buffered, vpnDirectHandshakeResponse{OK: true}); err != nil {
		_ = conn.Close()
		stream.closeWithError(err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	stream.attach(&vpnDirectConnStream{conn: conn})
}

func (m *AgentVPNDirectManager) handleHTTPConn(raw net.Conn, br *bufio.Reader) {
	ln := &vpnDirectSingleUseListener{conn: &vpnDirectBufferedConn{Conn: raw, reader: br}, done: make(chan struct{})}
	server := &http.Server{
		ReadHeaderTimeout: vpnDirectHandshakeTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer ln.Close()
			m.handleWebSocket(w, r)
		}),
	}
	_ = server.Serve(ln)
}

func (m *AgentVPNDirectManager) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Method != http.MethodGet || !m.hasPendingWSPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(vpnDirectHandshakeTimeout))
	messageType, payload, err := conn.ReadMessage()
	if err != nil || messageType != websocket.BinaryMessage {
		_ = conn.Close()
		return
	}
	stream, token, hello, err := m.consumeV2Session(payload, r.URL.Path)
	if err != nil {
		_ = conn.Close()
		return
	}
	exitNonce, err := vpnDirectRandomHex(16)
	if err != nil {
		_ = conn.Close()
		stream.closeWithError(err)
		return
	}
	accept := vpnDirectV2Accept{
		Version:    vpnDirectV2Version,
		SessionID:  hello.SessionID,
		EntryNonce: hello.Nonce,
		ExitNonce:  exitNonce,
		Timestamp:  time.Now().Unix(),
		Transport:  model.VPNDirectTransportWSTLS,
		Crypto:     model.VPNDirectCryptoV2,
	}
	accept.MAC = vpnDirectV2AcceptMAC(token, accept)
	if err := writeVPNDirectEncryptedControlFrame(conn, token, accept.SessionID, r.URL.Path, "accept", accept); err != nil {
		_ = conn.Close()
		stream.closeWithError(err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
	secureStream, err := newVPNDirectSecureStream(&vpnDirectWebSocketStream{conn: conn}, hello.SessionID, token, hello.Nonce, exitNonce, false)
	if err != nil {
		_ = conn.Close()
		stream.closeWithError(err)
		return
	}
	stream.attach(secureStream)
}

func (m *AgentVPNDirectManager) consumeSession(sessionID string, token string) (*vpnDirectPendingStream, error) {
	sessionID = strings.TrimSpace(sessionID)
	token = strings.TrimSpace(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	stream := m.sessions[sessionID]
	if stream == nil {
		return nil, errors.New("unknown VPN direct session")
	}
	if time.Now().Unix() > stream.expiresAtUnix {
		delete(m.sessions, sessionID)
		return nil, errors.New("VPN direct session expired")
	}
	if token == "" || token != stream.token {
		return nil, errors.New("invalid VPN direct session token")
	}
	delete(m.sessions, sessionID)
	return stream, nil
}

func (m *AgentVPNDirectManager) consumeV2Session(frame []byte, requestPath string) (*vpnDirectPendingStream, string, vpnDirectV2Hello, error) {
	requestPath = normalizeVPNDirectWSPath(requestPath)
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.pruneReplayNoncesLocked(now)
	for sessionID, stream := range m.sessions {
		if stream == nil {
			continue
		}
		if now.Unix() > stream.expiresAtUnix {
			delete(m.sessions, sessionID)
			continue
		}
		if normalizeVPNDirectTransport(stream.reqExtra["direct_transport"]) != model.VPNDirectTransportWSTLS || strings.TrimSpace(stream.reqExtra["direct_crypto"]) != model.VPNDirectCryptoV2 {
			continue
		}
		if normalizeVPNDirectWSPath(stream.reqExtra["direct_ws_path"]) != requestPath {
			continue
		}
		var hello vpnDirectV2Hello
		if err := openVPNDirectEncryptedControlFrame(stream.token, sessionID, requestPath, "hello", frame, &hello); err != nil {
			continue
		}
		if strings.TrimSpace(hello.SessionID) != sessionID {
			return nil, "", hello, errors.New("invalid VPN direct encrypted handshake session")
		}
		if err := validateVPNDirectV2Hello(stream.token, hello); err != nil {
			return nil, "", hello, err
		}
		nonceKey := sessionID + ":" + hello.Nonce
		if _, exists := m.replayNonces[nonceKey]; exists {
			return nil, "", hello, errors.New("replayed VPN direct handshake")
		}
		m.replayNonces[nonceKey] = now.Add(vpnDirectV2ClockSkew)
		delete(m.sessions, sessionID)
		return stream, stream.token, hello, nil
	}
	return nil, "", vpnDirectV2Hello{}, errors.New("unknown or invalid VPN direct session")
}

func (m *AgentVPNDirectManager) hasPendingWSPath(path string) bool {
	path = normalizeVPNDirectWSPath(path)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, stream := range m.sessions {
		if stream == nil {
			continue
		}
		if normalizeVPNDirectTransport(stream.reqExtra["direct_transport"]) != model.VPNDirectTransportWSTLS || strings.TrimSpace(stream.reqExtra["direct_crypto"]) != model.VPNDirectCryptoV2 {
			continue
		}
		if normalizeVPNDirectWSPath(stream.reqExtra["direct_ws_path"]) == path {
			return true
		}
	}
	return false
}

func (m *AgentVPNDirectManager) pruneReplayNoncesLocked(now time.Time) {
	for nonce, expiresAt := range m.replayNonces {
		if now.After(expiresAt) {
			delete(m.replayNonces, nonce)
		}
	}
}

type vpnDirectPendingStream struct {
	manager       *AgentVPNDirectManager
	sessionID     string
	token         string
	expiresAtUnix int64
	reqExtra      map[string]string
	ready         chan struct{}
	done          chan struct{}
	once          sync.Once
	mu            sync.Mutex
	stream        vpnIOStream
	err           error
}

func newVPNDirectPendingStream(manager *AgentVPNDirectManager, req model.VPNControlRequest) *vpnDirectPendingStream {
	return &vpnDirectPendingStream{
		manager:       manager,
		sessionID:     req.SessionID,
		token:         req.Token,
		expiresAtUnix: req.ExpiresAtUnix,
		reqExtra:      cloneVPNDirectExtra(req.Extra),
		ready:         make(chan struct{}),
		done:          make(chan struct{}),
	}
}

func (s *vpnDirectPendingStream) attach(stream vpnIOStream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		_ = stream.CloseSend()
		return
	default:
	}
	s.stream = stream
	close(s.ready)
}

func (s *vpnDirectPendingStream) closeWithError(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.CloseSend()
}

func (s *vpnDirectPendingStream) wait() (vpnIOStream, error) {
	select {
	case <-s.ready:
	case <-s.done:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stream != nil {
		return s.stream, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return nil, io.ErrClosedPipe
}

func (s *vpnDirectPendingStream) Send(data *pb.IOStreamData) error {
	stream, err := s.wait()
	if err != nil {
		return err
	}
	return stream.Send(data)
}

func (s *vpnDirectPendingStream) Recv() (*pb.IOStreamData, error) {
	stream, err := s.wait()
	if err != nil {
		return nil, err
	}
	return stream.Recv()
}

func (s *vpnDirectPendingStream) CloseSend() error {
	s.once.Do(func() {
		if s.manager != nil {
			s.manager.unregister(s.sessionID, s)
		}
		s.mu.Lock()
		stream := s.stream
		s.mu.Unlock()
		if stream != nil {
			_ = stream.CloseSend()
		}
		close(s.done)
	})
	return nil
}

type vpnDirectConnStream struct {
	conn net.Conn
	mu   sync.Mutex
}

func (s *vpnDirectConnStream) Send(data *pb.IOStreamData) error {
	if s == nil || s.conn == nil {
		return io.ErrClosedPipe
	}
	payload := data.GetData()
	if len(payload) > vpnDirectMaxWireFrameSize {
		return fmt.Errorf("VPN direct frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.conn.Write(header[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := s.conn.Write(payload)
	return err
}

func (s *vpnDirectConnStream) Recv() (*pb.IOStreamData, error) {
	if s == nil || s.conn == nil {
		return nil, io.ErrClosedPipe
	}
	payload, err := readVPNDirectFrame(s.conn)
	if err != nil {
		return nil, err
	}
	return &pb.IOStreamData{Data: payload}, nil
}

func (s *vpnDirectConnStream) CloseSend() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

type vpnDirectWebSocketStream struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *vpnDirectWebSocketStream) Send(data *pb.IOStreamData) error {
	if s == nil || s.conn == nil {
		return io.ErrClosedPipe
	}
	payload := data.GetData()
	if len(payload) > vpnDirectMaxWireFrameSize {
		return fmt.Errorf("VPN direct frame too large: %d", len(payload))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(websocket.BinaryMessage, append([]byte(nil), payload...))
}

func (s *vpnDirectWebSocketStream) Recv() (*pb.IOStreamData, error) {
	if s == nil || s.conn == nil {
		return nil, io.ErrClosedPipe
	}
	for {
		messageType, payload, err := s.conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		if len(payload) > vpnDirectMaxWireFrameSize {
			return nil, fmt.Errorf("VPN direct frame too large: %d", len(payload))
		}
		return &pb.IOStreamData{Data: payload}, nil
	}
}

func (s *vpnDirectWebSocketStream) CloseSend() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

type vpnDirectSecureStream struct {
	base      vpnIOStream
	sendAEAD  cipherAEAD
	recvAEAD  cipherAEAD
	sendNonce []byte
	recvNonce []byte
	sendCount uint64
	recvCount uint64
	sendMu    sync.Mutex
	sessionID string
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

func newVPNDirectSecureStream(base vpnIOStream, sessionID string, token string, entryNonce string, exitNonce string, entrySide bool) (vpnIOStream, error) {
	material, err := deriveVPNDirectV2Material(sessionID, token, entryNonce, exitNonce)
	if err != nil {
		return nil, err
	}
	entryToExit, err := chacha20poly1305.NewX(material.entryToExitKey)
	if err != nil {
		return nil, err
	}
	exitToEntry, err := chacha20poly1305.NewX(material.exitToEntryKey)
	if err != nil {
		return nil, err
	}
	stream := &vpnDirectSecureStream{
		base:      base,
		sessionID: sessionID,
	}
	if entrySide {
		stream.sendAEAD = entryToExit
		stream.recvAEAD = exitToEntry
		stream.sendNonce = material.entryNoncePrefix
		stream.recvNonce = material.exitNoncePrefix
	} else {
		stream.sendAEAD = exitToEntry
		stream.recvAEAD = entryToExit
		stream.sendNonce = material.exitNoncePrefix
		stream.recvNonce = material.entryNoncePrefix
	}
	return stream, nil
}

func (s *vpnDirectSecureStream) Send(data *pb.IOStreamData) error {
	if s == nil || s.base == nil {
		return io.ErrClosedPipe
	}
	plaintext := data.GetData()
	if len(plaintext) > vpnDirectMaxFrameSize {
		return fmt.Errorf("VPN direct frame too large: %d", len(plaintext))
	}
	s.sendMu.Lock()
	counter := s.sendCount
	s.sendCount++
	nonce := vpnDirectV2Nonce(s.sendNonce, counter)
	ad := vpnDirectV2AdditionalData(s.sessionID, counter)
	ciphertext := s.sendAEAD.Seal(nil, nonce, plaintext, ad)
	s.sendMu.Unlock()
	return s.base.Send(&pb.IOStreamData{Data: ciphertext})
}

func (s *vpnDirectSecureStream) Recv() (*pb.IOStreamData, error) {
	if s == nil || s.base == nil {
		return nil, io.ErrClosedPipe
	}
	frame, err := s.base.Recv()
	if err != nil {
		return nil, err
	}
	counter := s.recvCount
	s.recvCount++
	nonce := vpnDirectV2Nonce(s.recvNonce, counter)
	ad := vpnDirectV2AdditionalData(s.sessionID, counter)
	plaintext, err := s.recvAEAD.Open(nil, nonce, frame.GetData(), ad)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > vpnDirectMaxFrameSize {
		return nil, fmt.Errorf("VPN direct frame too large: %d", len(plaintext))
	}
	return &pb.IOStreamData{Data: plaintext}, nil
}

func (s *vpnDirectSecureStream) CloseSend() error {
	if s == nil || s.base == nil {
		return nil
	}
	return s.base.CloseSend()
}

func readVPNDirectFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > vpnDirectMaxFrameSize {
		return nil, fmt.Errorf("VPN direct frame too large: %d", size)
	}
	payload := make([]byte, size)
	if size == 0 {
		return payload, nil
	}
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func writeVPNDirectJSON(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func readVPNDirectJSON(r io.Reader, value any) error {
	payload, err := readVPNDirectFrame(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, value)
}

func loadOrCreateVPNDirectCertificate(certPath string, keyPath string) (tls.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil && len(cert.Certificate) > 0 {
		return cert, vpnDirectCertFingerprint(cert.Certificate[0]), nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return tls.Certificate{}, "", err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nezha-agent-vpn-direct"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return tls.Certificate{}, "", err
	}
	cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, vpnDirectCertFingerprint(certDER), nil
}

func vpnDirectCertFingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

func normalizeVPNDirectSHA256(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "sha256:")
	value = strings.ReplaceAll(value, ":", "")
	return value
}

func defaultVPNDirectCertPath() string {
	return filepath.Join(defaultVPNDirectWorkDir(), "direct", "cert.pem")
}

func defaultVPNDirectKeyPath() string {
	return filepath.Join(defaultVPNDirectWorkDir(), "direct", "key.pem")
}

func defaultVPNDirectWorkDir() string {
	if strings.TrimSpace(agentConfig.VPNStateDir) != "" {
		return strings.TrimSpace(agentConfig.VPNStateDir)
	}
	return defaultVPNWorkDir()
}

func listenerPort(ln net.Listener) (int, error) {
	_, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid VPN direct listen port %q", portText)
	}
	return port, nil
}

type vpnDirectV2Material struct {
	entryToExitKey   []byte
	exitToEntryKey   []byte
	entryNoncePrefix []byte
	exitNoncePrefix  []byte
}

func deriveVPNDirectV2Material(sessionID string, token string, entryNonce string, exitNonce string) (vpnDirectV2Material, error) {
	salt := []byte(strings.Join([]string{strings.TrimSpace(sessionID), entryNonce, exitNonce}, "|"))
	key, err := hkdf.Key(sha256.New, []byte(token), salt, "nezha-agent-vpn-direct-v2", 64+32)
	if err != nil {
		return vpnDirectV2Material{}, err
	}
	return vpnDirectV2Material{
		entryToExitKey:   append([]byte(nil), key[:32]...),
		exitToEntryKey:   append([]byte(nil), key[32:64]...),
		entryNoncePrefix: append([]byte(nil), key[64:80]...),
		exitNoncePrefix:  append([]byte(nil), key[80:96]...),
	}, nil
}

func vpnDirectV2Nonce(prefix []byte, counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[16:], counter)
	return nonce
}

func vpnDirectV2AdditionalData(sessionID string, counter uint64) []byte {
	return []byte(fmt.Sprintf("nezha-agent-vpn-direct-v2|%s|%d", sessionID, counter))
}

func writeVPNDirectEncryptedControlFrame(conn *websocket.Conn, token string, sessionID string, wsPath string, label string, value any) error {
	payload, err := sealVPNDirectEncryptedControlFrame(token, sessionID, wsPath, label, value)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.BinaryMessage, payload)
}

func readVPNDirectEncryptedControlFrame(conn *websocket.Conn, token string, sessionID string, wsPath string, label string, value any) error {
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if messageType != websocket.BinaryMessage {
		return errors.New("invalid VPN direct control frame type")
	}
	return openVPNDirectEncryptedControlFrame(token, sessionID, wsPath, label, payload, value)
}

func sealVPNDirectEncryptedControlFrame(token string, sessionID string, wsPath string, label string, value any) ([]byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	nonce, err := vpnDirectRandomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aead, err := newVPNDirectControlAEAD(token, sessionID, wsPath, label)
	if err != nil {
		return nil, err
	}
	ad := vpnDirectControlAdditionalData(sessionID, wsPath, label)
	out := make([]byte, 0, len(nonce)+len(plaintext)+chacha20poly1305.Overhead)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, ad)
	return out, nil
}

func openVPNDirectEncryptedControlFrame(token string, sessionID string, wsPath string, label string, frame []byte, value any) error {
	if len(frame) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return errors.New("invalid VPN direct encrypted control frame")
	}
	aead, err := newVPNDirectControlAEAD(token, sessionID, wsPath, label)
	if err != nil {
		return err
	}
	nonce := frame[:chacha20poly1305.NonceSizeX]
	ciphertext := frame[chacha20poly1305.NonceSizeX:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, vpnDirectControlAdditionalData(sessionID, wsPath, label))
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, value)
}

func newVPNDirectControlAEAD(token string, sessionID string, wsPath string, label string) (cipherAEAD, error) {
	info := strings.Join([]string{"nezha-agent-vpn-direct-v2-control", label, normalizeVPNDirectWSPath(wsPath)}, "|")
	key, err := hkdf.Key(sha256.New, []byte(token), []byte(strings.TrimSpace(sessionID)), info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(key)
}

func vpnDirectControlAdditionalData(sessionID string, wsPath string, label string) []byte {
	return []byte(strings.Join([]string{"nezha-agent-vpn-direct-v2-control", label, strings.TrimSpace(sessionID), normalizeVPNDirectWSPath(wsPath)}, "|"))
}

func validateVPNDirectV2Hello(token string, hello vpnDirectV2Hello) error {
	if hello.Version != vpnDirectV2Version {
		return errors.New("unsupported VPN direct handshake version")
	}
	if strings.TrimSpace(hello.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if normalizeVPNDirectTransport(hello.Transport) != model.VPNDirectTransportWSTLS {
		return errors.New("unsupported VPN direct transport")
	}
	if strings.TrimSpace(hello.Crypto) != model.VPNDirectCryptoV2 {
		return errors.New("unsupported VPN direct crypto")
	}
	if _, err := hex.DecodeString(hello.Nonce); err != nil || len(hello.Nonce) != 32 {
		return errors.New("invalid VPN direct nonce")
	}
	if skew := time.Since(time.Unix(hello.Timestamp, 0)); skew < -vpnDirectV2ClockSkew || skew > vpnDirectV2ClockSkew {
		return errors.New("VPN direct handshake timestamp expired")
	}
	expected := vpnDirectV2HelloMAC(token, hello)
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(hello.MAC))) {
		return errors.New("invalid VPN direct handshake mac")
	}
	return nil
}

func validateVPNDirectV2Accept(token string, hello vpnDirectV2Hello, accept vpnDirectV2Accept) error {
	if accept.Version != vpnDirectV2Version {
		return errors.New("unsupported VPN direct accept version")
	}
	if accept.SessionID != hello.SessionID || accept.EntryNonce != hello.Nonce {
		return errors.New("invalid VPN direct accept session")
	}
	if normalizeVPNDirectTransport(accept.Transport) != model.VPNDirectTransportWSTLS {
		return errors.New("invalid VPN direct accept transport")
	}
	if accept.Crypto != model.VPNDirectCryptoV2 {
		return errors.New("invalid VPN direct accept crypto")
	}
	if _, err := hex.DecodeString(accept.ExitNonce); err != nil || len(accept.ExitNonce) != 32 {
		return errors.New("invalid VPN direct accept nonce")
	}
	if skew := time.Since(time.Unix(accept.Timestamp, 0)); skew < -vpnDirectV2ClockSkew || skew > vpnDirectV2ClockSkew {
		return errors.New("VPN direct accept timestamp expired")
	}
	expected := vpnDirectV2AcceptMAC(token, accept)
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(accept.MAC))) {
		return errors.New("invalid VPN direct accept mac")
	}
	return nil
}

func vpnDirectV2HelloMAC(token string, hello vpnDirectV2Hello) string {
	payload := strings.Join([]string{
		strconv.Itoa(hello.Version),
		hello.SessionID,
		strconv.FormatInt(hello.Timestamp, 10),
		hello.Nonce,
		normalizeVPNDirectTransport(hello.Transport),
		hello.Crypto,
	}, "\n")
	return vpnDirectHMAC(token, "hello", payload)
}

func vpnDirectV2AcceptMAC(token string, accept vpnDirectV2Accept) string {
	payload := strings.Join([]string{
		strconv.Itoa(accept.Version),
		accept.SessionID,
		accept.EntryNonce,
		accept.ExitNonce,
		strconv.FormatInt(accept.Timestamp, 10),
		normalizeVPNDirectTransport(accept.Transport),
		accept.Crypto,
	}, "\n")
	return vpnDirectHMAC(token, "accept", payload)
}

func vpnDirectHMAC(token string, label string, payload string) string {
	key := sha256.Sum256([]byte("nezha-agent-vpn-direct-v2|" + label + "|" + token))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func vpnDirectRandomHex(size int) (string, error) {
	buf, err := vpnDirectRandomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func vpnDirectRandomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func vpnDirectWSURL(req model.VPNControlRequest) (string, string) {
	address := strings.TrimSpace(req.Extra["direct_address"])
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	serverName := strings.TrimSpace(req.Extra["direct_tls_server_name"])
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	u := url.URL{
		Scheme: "wss",
		Host:   address,
		Path:   normalizeVPNDirectWSPath(req.Extra["direct_ws_path"]),
	}
	return u.String(), serverName
}

func vpnDirectTLSVerifyEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "0", "no", "off", "insecure":
		return false
	default:
		return true
	}
}

func vpnDirectPeerCertificateVerifier(certSHA string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("missing VPN direct peer certificate")
		}
		sum := sha256.Sum256(rawCerts[0])
		if hex.EncodeToString(sum[:]) != certSHA {
			return errors.New("VPN direct peer certificate fingerprint mismatch")
		}
		return nil
	}
}

func normalizeVPNDirectTransport(value string) string {
	switch strings.TrimSpace(value) {
	case model.VPNDirectTransportWSTLS:
		return model.VPNDirectTransportWSTLS
	default:
		return model.VPNDirectTransportTCPTLS
	}
}

func normalizeVPNDirectWSPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return vpnDirectDefaultWSPath
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Path != "" {
		value = parsed.Path
	}
	return value
}

func cloneVPNDirectExtra(extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return map[string]string{"direct_ws_path": vpnDirectDefaultWSPath}
	}
	clone := make(map[string]string, len(extra)+1)
	for key, value := range extra {
		clone[key] = value
	}
	if strings.TrimSpace(clone["direct_ws_path"]) == "" {
		clone["direct_ws_path"] = vpnDirectDefaultWSPath
	}
	return clone
}

type vpnDirectBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *vpnDirectBufferedConn) Read(p []byte) (int, error) {
	if c == nil || c.reader == nil {
		return c.Conn.Read(p)
	}
	return c.reader.Read(p)
}

type vpnDirectSingleUseListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *vpnDirectSingleUseListener) Accept() (net.Conn, error) {
	if l.done == nil {
		l.done = make(chan struct{})
	}
	var conn net.Conn
	l.once.Do(func() {
		conn = l.conn
	})
	if conn != nil {
		return conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *vpnDirectSingleUseListener) Close() error {
	if l == nil {
		return nil
	}
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *vpnDirectSingleUseListener) Addr() net.Addr {
	if l == nil || l.conn == nil {
		return nil
	}
	return l.conn.LocalAddr()
}
