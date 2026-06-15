package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

const (
	vpnDirectHandshakeTimeout = 10 * time.Second
	vpnDirectDialTimeout      = 8 * time.Second
	vpnDirectMaxFrameSize     = 4 << 20
)

var defaultAgentVPNDirectManager = NewAgentVPNDirectManager()

type AgentVPNDirectManager struct {
	mu       sync.Mutex
	listener net.Listener
	cert     tls.Certificate
	certSHA  string
	sessions map[string]*vpnDirectPendingStream
}

type vpnDirectHandshake struct {
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
}

type vpnDirectHandshakeResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func NewAgentVPNDirectManager() *AgentVPNDirectManager {
	return &AgentVPNDirectManager{
		sessions: map[string]*vpnDirectPendingStream{},
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
	printf("Agent VPN direct relay listening on %s", ln.Addr().String())
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
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
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
	m.mu.Lock()
	cert := m.cert
	m.mu.Unlock()
	conn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	_ = conn.SetDeadline(time.Now().Add(vpnDirectHandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	var handshake vpnDirectHandshake
	if err := readVPNDirectJSON(conn, &handshake); err != nil {
		_ = conn.Close()
		return
	}
	stream, err := m.consumeSession(handshake.SessionID, handshake.Token)
	if err != nil {
		_ = writeVPNDirectJSON(conn, vpnDirectHandshakeResponse{OK: false, Error: err.Error()})
		_ = conn.Close()
		return
	}
	if err := writeVPNDirectJSON(conn, vpnDirectHandshakeResponse{OK: true}); err != nil {
		_ = conn.Close()
		stream.closeWithError(err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	stream.attach(&vpnDirectConnStream{conn: conn})
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

type vpnDirectPendingStream struct {
	manager       *AgentVPNDirectManager
	sessionID     string
	token         string
	expiresAtUnix int64
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
	if len(payload) > vpnDirectMaxFrameSize {
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
