package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

const vpnBridgeBufferSize = 32 * 1024
const vpnMuxFrameHeaderSize = 17
const vpnMuxFrameTypeOpen byte = 1
const vpnMuxFrameTypeData byte = 2
const vpnMuxFrameTypeClose byte = 3

var vpnMuxFrameMagic = [4]byte{'N', 'Z', 'V', 'M'}

type AgentVPNBridge struct {
	cancel context.CancelFunc
	close  func() error
	stats  *vpnBridgeStats
}

type vpnBridgeStats struct {
	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64
	activeConns   atomic.Uint32
}

func (s *vpnBridgeStats) Snapshot() (uint64, uint64, uint32) {
	if s == nil {
		return 0, 0, 0
	}
	return s.uploadBytes.Load(), s.downloadBytes.Load(), s.activeConns.Load()
}

func startAgentVPNBridge(ctx context.Context, req model.VPNControlRequest, stream vpnIOStream) (*AgentVPNBridge, error) {
	if req.Role == model.VPNRoleEntry {
		return startAgentVPNEntryBridge(ctx, req, stream)
	}
	if req.Role == model.VPNRoleExit {
		return startAgentVPNExitBridge(ctx, req, stream)
	}
	return nil, nil
}

func startAgentVPNEntryBridge(ctx context.Context, req model.VPNControlRequest, stream vpnIOStream) (*AgentVPNBridge, error) {
	addr := firstNonEmpty(req.Extra["bridge_addr"], defaultVPNEntryBridge)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stats := &vpnBridgeStats{}
	bridge := &AgentVPNBridge{
		cancel: cancel,
		stats:  stats,
	}
	mux := newVPNMuxBridge(ctx, newVPNRelayByteStream(stream), nil, stats)
	bridge.close = func() error {
		_ = ln.Close()
		return mux.Close()
	}
	go mux.runReadLoop()
	go func() {
		defer bridge.Close()
		var active sync.WaitGroup
		var activeCount atomic.Int32
		defer active.Wait()
		maxConnections := int32(req.Limits.MaxConnections)
		if maxConnections <= 0 {
			maxConnections = 1
		}
		idleTimeout := time.Duration(req.Limits.IdleTimeoutSeconds) * time.Second
		mux.idleTimeout = idleTimeout
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if activeCount.Load() >= maxConnections {
				_ = conn.Close()
				continue
			}
			stats.activeConns.Store(uint32(activeCount.Add(1)))
			active.Add(1)
			go func() {
				defer active.Done()
				defer stats.activeConns.Store(uint32(activeCount.Add(-1)))
				id := mux.nextConnID()
				if idleTimeout > 0 {
					_ = conn.SetDeadline(time.Now().Add(idleTimeout))
				}
				if err := mux.addLocalConn(id, conn); err != nil {
					_ = conn.Close()
					return
				}
				if err := mux.sendFrame(vpnMuxFrameTypeOpen, id, nil); err != nil {
					mux.closeConn(id)
					return
				}
				mux.copyConnToMux(id, conn)
			}()
		}
	}()
	return bridge, nil
}

func startAgentVPNExitBridge(ctx context.Context, req model.VPNControlRequest, stream vpnIOStream) (*AgentVPNBridge, error) {
	addr := firstNonEmpty(req.Extra["bridge_listen"], defaultVPNExitBridge)
	ctx, cancel := context.WithCancel(ctx)
	mux := newVPNMuxBridge(ctx, newVPNRelayByteStream(stream), func(ctx context.Context) (net.Conn, error) {
		return dialVPNBridgeTarget(ctx, addr)
	}, nil)
	bridge := &AgentVPNBridge{
		cancel: cancel,
		close:  mux.Close,
	}
	go mux.runReadLoop()
	return bridge, nil
}

func dialVPNBridgeTarget(ctx context.Context, address string) (net.Conn, error) {
	var lastErr error
	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, lastErr
}

func (b *AgentVPNBridge) Close() error {
	if b == nil {
		return nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	if b.close != nil {
		return b.close()
	}
	return nil
}

func bridgeVPNRelayStreamToConn(ctx context.Context, stream vpnIOStream, conn net.Conn) error {
	if stream == nil || conn == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer stream.CloseSend()
	defer conn.Close()

	errCh := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = conn.Close()
			_ = stream.CloseSend()
			cancel()
		})
	}

	go func() {
		errCh <- copyVPNStreamToConn(ctx, stream, conn)
		closeBoth()
	}()
	go func() {
		errCh <- copyVPNConnToStream(ctx, conn, stream)
		closeBoth()
	}()

	err := <-errCh
	if isExpectedVPNBridgeClose(err) {
		return nil
	}
	return err
}

func copyVPNStreamToConn(ctx context.Context, stream vpnIOStream, conn net.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		data := frame.GetData()
		if len(data) == 0 {
			continue
		}
		if _, err := conn.Write(data); err != nil {
			return err
		}
	}
}

func copyVPNConnToStream(ctx context.Context, conn net.Conn, stream vpnIOStream) error {
	buf := make([]byte, vpnBridgeBufferSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := stream.Send(&pb.IOStreamData{Data: append([]byte(nil), buf[:n]...)}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			return err
		}
	}
}

func isExpectedVPNBridgeClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

type vpnRelayByteStream struct {
	stream  vpnIOStream
	readBuf []byte
	writeMu sync.Mutex
}

func newVPNRelayByteStream(stream vpnIOStream) *vpnRelayByteStream {
	return &vpnRelayByteStream{stream: stream}
}

func (s *vpnRelayByteStream) Read(p []byte) (int, error) {
	for len(s.readBuf) == 0 {
		frame, err := s.stream.Recv()
		if err != nil {
			return 0, err
		}
		s.readBuf = frame.GetData()
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *vpnRelayByteStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.stream.Send(&pb.IOStreamData{Data: append([]byte(nil), p...)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *vpnRelayByteStream) Close() error {
	return s.stream.CloseSend()
}

type vpnMuxFrame struct {
	Type    byte
	ConnID  uint64
	Payload []byte
}

type vpnMuxBridge struct {
	ctx         context.Context
	cancel      context.CancelFunc
	rw          io.ReadWriteCloser
	stats       *vpnBridgeStats
	sendMu      sync.Mutex
	mu          sync.Mutex
	conns       map[uint64]net.Conn
	nextID      atomic.Uint64
	idleTimeout time.Duration
	dialTarget  func(context.Context) (net.Conn, error)
}

func newVPNMuxBridge(ctx context.Context, rw io.ReadWriteCloser, dialTarget func(context.Context) (net.Conn, error), stats *vpnBridgeStats) *vpnMuxBridge {
	ctx, cancel := context.WithCancel(ctx)
	return &vpnMuxBridge{
		ctx:        ctx,
		cancel:     cancel,
		rw:         rw,
		stats:      stats,
		conns:      make(map[uint64]net.Conn),
		dialTarget: dialTarget,
	}
}

func (m *vpnMuxBridge) nextConnID() uint64 {
	return m.nextID.Add(1)
}

func (m *vpnMuxBridge) addLocalConn(id uint64, conn net.Conn) error {
	if conn == nil {
		return errors.New("VPN mux connection is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.conns[id]; exists {
		return errors.New("VPN mux connection id already exists")
	}
	m.conns[id] = conn
	return nil
}

func (m *vpnMuxBridge) getConn(id uint64) net.Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns[id]
}

func (m *vpnMuxBridge) removeConn(id uint64) (net.Conn, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn := m.conns[id]
	if conn == nil {
		return nil, false
	}
	delete(m.conns, id)
	return conn, true
}

func (m *vpnMuxBridge) closeConn(id uint64) {
	conn, ok := m.removeConn(id)
	if ok {
		_ = conn.Close()
	}
}

func (m *vpnMuxBridge) Close() error {
	if m == nil {
		return nil
	}
	m.cancel()
	m.mu.Lock()
	for id, conn := range m.conns {
		_ = conn.Close()
		delete(m.conns, id)
	}
	m.mu.Unlock()
	if m.rw != nil {
		return m.rw.Close()
	}
	return nil
}

func (m *vpnMuxBridge) runReadLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}
		frame, err := readVPNMuxFrame(m.rw)
		if err != nil {
			_ = m.Close()
			return
		}
		m.handleFrame(frame)
	}
}

func (m *vpnMuxBridge) handleFrame(frame vpnMuxFrame) {
	switch frame.Type {
	case vpnMuxFrameTypeOpen:
		if m.dialTarget == nil {
			_ = m.sendFrame(vpnMuxFrameTypeClose, frame.ConnID, nil)
			return
		}
		conn, err := m.dialTarget(m.ctx)
		if err != nil {
			printf("VPN mux dial target failed for connection %d: %v", frame.ConnID, err)
			_ = m.sendFrame(vpnMuxFrameTypeClose, frame.ConnID, nil)
			return
		}
		if err := m.addLocalConn(frame.ConnID, conn); err != nil {
			_ = conn.Close()
			_ = m.sendFrame(vpnMuxFrameTypeClose, frame.ConnID, nil)
			return
		}
		go m.copyConnToMux(frame.ConnID, conn)
	case vpnMuxFrameTypeData:
		conn := m.getConn(frame.ConnID)
		if conn == nil {
			_ = m.sendFrame(vpnMuxFrameTypeClose, frame.ConnID, nil)
			return
		}
		refreshVPNConnDeadline(conn, m.idleTimeout)
		if _, err := conn.Write(frame.Payload); err != nil {
			m.closeConn(frame.ConnID)
			_ = m.sendFrame(vpnMuxFrameTypeClose, frame.ConnID, nil)
		} else if m.stats != nil {
			m.stats.downloadBytes.Add(uint64(len(frame.Payload)))
		}
	case vpnMuxFrameTypeClose:
		m.closeConn(frame.ConnID)
	}
}

func (m *vpnMuxBridge) copyConnToMux(id uint64, conn net.Conn) {
	buf := make([]byte, vpnBridgeBufferSize)
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}
		n, err := conn.Read(buf)
		if n > 0 {
			refreshVPNConnDeadline(conn, m.idleTimeout)
			if sendErr := m.sendFrame(vpnMuxFrameTypeData, id, append([]byte(nil), buf[:n]...)); sendErr != nil {
				m.closeConn(id)
				return
			}
			if m.stats != nil {
				m.stats.uploadBytes.Add(uint64(n))
			}
		}
		if err != nil {
			if _, ok := m.removeConn(id); ok {
				_ = conn.Close()
			}
			if m.ctx.Err() == nil {
				_ = m.sendFrame(vpnMuxFrameTypeClose, id, nil)
			}
			return
		}
	}
}

func refreshVPNConnDeadline(conn net.Conn, idleTimeout time.Duration) {
	if conn == nil || idleTimeout <= 0 {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(idleTimeout))
}

func (m *vpnMuxBridge) sendFrame(frameType byte, connID uint64, payload []byte) error {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	return writeVPNMuxFrame(m.rw, vpnMuxFrame{Type: frameType, ConnID: connID, Payload: payload})
}

func writeVPNMuxFrame(writer io.Writer, frame vpnMuxFrame) error {
	header := make([]byte, vpnMuxFrameHeaderSize)
	copy(header[:4], vpnMuxFrameMagic[:])
	header[4] = frame.Type
	binary.BigEndian.PutUint64(header[5:13], frame.ConnID)
	binary.BigEndian.PutUint32(header[13:17], uint32(len(frame.Payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(frame.Payload) == 0 {
		return nil
	}
	_, err := writer.Write(frame.Payload)
	return err
}

func readVPNMuxFrame(reader io.Reader) (vpnMuxFrame, error) {
	header := make([]byte, vpnMuxFrameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return vpnMuxFrame{}, err
	}
	var magic [4]byte
	copy(magic[:], header[:4])
	if magic != vpnMuxFrameMagic {
		return vpnMuxFrame{}, errors.New("invalid VPN mux frame magic")
	}
	payloadLen := binary.BigEndian.Uint32(header[13:17])
	frame := vpnMuxFrame{
		Type:    header[4],
		ConnID:  binary.BigEndian.Uint64(header[5:13]),
		Payload: make([]byte, payloadLen),
	}
	if payloadLen > 0 {
		if _, err := io.ReadFull(reader, frame.Payload); err != nil {
			return vpnMuxFrame{}, err
		}
	}
	return frame, nil
}
