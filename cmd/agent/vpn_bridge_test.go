package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestVPNBridgeCopiesRemoteFramesToLocalConn(t *testing.T) {
	local, sidecar := net.Pipe()
	defer sidecar.Close()
	stream := newScriptedVPNIOStream([]*pb.IOStreamData{
		{Data: []byte("from-dashboard")},
	}, io.EOF)

	done := make(chan error, 1)
	go func() {
		done <- bridgeVPNRelayStreamToConn(context.Background(), stream, local)
	}()

	buf := make([]byte, len("from-dashboard"))
	if _, err := io.ReadFull(sidecar, buf); err != nil {
		t.Fatalf("read sidecar conn: %v", err)
	}
	if string(buf) != "from-dashboard" {
		t.Fatalf("remote frame not copied to local conn: %q", buf)
	}
	sidecar.Close()
	waitVPNBridgeDone(t, done)
}

func TestVPNBridgeCopiesLocalConnDataToRemoteFrames(t *testing.T) {
	local, sidecar := net.Pipe()
	defer sidecar.Close()
	stream := newBlockingScriptedVPNIOStream()

	done := make(chan error, 1)
	go func() {
		done <- bridgeVPNRelayStreamToConn(context.Background(), stream, local)
	}()

	if _, err := sidecar.Write([]byte("from-sidecar")); err != nil {
		t.Fatalf("write sidecar conn: %v", err)
	}
	waitForVPNStreamSentFrame(t, stream, "from-sidecar")
	stream.finish(io.EOF)
	sidecar.Close()
	waitVPNBridgeDone(t, done)
}

func TestVPNEntryBridgeRejectsConnectionsAbovePolicyLimit(t *testing.T) {
	addr := freeLocalTCPAddrForTest(t)
	stream := newBlockingScriptedVPNIOStream()
	bridge, err := startAgentVPNEntryBridge(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-limit",
		Role:      model.VPNRoleEntry,
		Extra: map[string]string{
			"bridge_addr": addr,
		},
		Limits: model.VPNLimits{
			MaxConnections: 1,
		},
	}, stream)
	if err != nil {
		t.Fatalf("start entry bridge: %v", err)
	}
	defer bridge.Close()

	first, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial first bridge connection: %v", err)
	}
	defer first.Close()
	if _, err := first.Write([]byte("first-prime")); err != nil {
		t.Fatalf("prime first connection: %v", err)
	}
	waitForVPNStreamSentMuxPayload(t, stream, "first-prime")
	waitVPNBridgeActiveConns(t, bridge, 1)

	second, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial second bridge connection: %v", err)
	}
	defer second.Close()
	if _, err := second.Write([]byte("blocked")); err != nil && !isExpectedVPNBridgeClose(err) {
		t.Fatalf("write second connection: %v", err)
	}
	buf := make([]byte, 1)
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	n, err := second.Read(buf)
	if err == nil || n != 0 {
		t.Fatalf("second connection must be closed by max_connections, read n=%d err=%v", n, err)
	}
	assertVPNStreamMuxPayloadNotSent(t, stream, "blocked", 200*time.Millisecond)

	if _, err := first.Write([]byte("first-ok")); err != nil {
		t.Fatalf("first connection should remain active: %v", err)
	}
	waitForVPNStreamSentMuxPayload(t, stream, "first-ok")
}

func TestVPNEntryBridgeClosesIdleConnectionsAfterPolicyTimeout(t *testing.T) {
	addr := freeLocalTCPAddrForTest(t)
	stream := newBlockingScriptedVPNIOStream()
	bridge, err := startAgentVPNEntryBridge(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-idle",
		Role:      model.VPNRoleEntry,
		Extra: map[string]string{
			"bridge_addr": addr,
		},
		Limits: model.VPNLimits{
			MaxConnections:     1,
			IdleTimeoutSeconds: 1,
		},
	}, stream)
	if err != nil {
		t.Fatalf("start entry bridge: %v", err)
	}
	defer bridge.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial bridge connection: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err == nil || n != 0 {
		t.Fatalf("idle connection must be closed by policy timeout, read n=%d err=%v", n, err)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("idle connection timed out instead of being actively closed: %v", err)
	}
}

func TestVPNEntryBridgeReportsRelayReadFailure(t *testing.T) {
	addr := freeLocalTCPAddrForTest(t)
	stream := newBlockingScriptedVPNIOStream()
	bridge, err := startAgentVPNEntryBridge(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-relay-read-failure",
		Role:      model.VPNRoleEntry,
		Extra: map[string]string{
			"bridge_addr": addr,
		},
	}, stream)
	if err != nil {
		t.Fatalf("start entry bridge: %v", err)
	}
	defer bridge.Close()

	stream.finish(io.ErrUnexpectedEOF)
	waitVPNBridgeFailure(t, bridge.Done(), io.ErrUnexpectedEOF)
}

func TestVPNEntryBridgeReportsRelayWriteFailure(t *testing.T) {
	addr := freeLocalTCPAddrForTest(t)
	stream := newBlockingScriptedVPNIOStream()
	stream.sendErr = io.ErrClosedPipe
	bridge, err := startAgentVPNEntryBridge(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-relay-write-failure",
		Role:      model.VPNRoleEntry,
		Extra: map[string]string{
			"bridge_addr": addr,
		},
	}, stream)
	if err != nil {
		t.Fatalf("start entry bridge: %v", err)
	}
	defer bridge.Close()

	conn, err := dialEventuallyForTest(addr)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close()
	waitVPNBridgeFailure(t, bridge.Done(), io.ErrClosedPipe)
}

func TestVPNBridgeMultiplexesConcurrentEntryConnectionsThroughOneRelay(t *testing.T) {
	entryStream, exitStream := newPairedVPNIOStreams()
	exitTargetAddr, closeExitTarget := startVPNBridgeEchoTarget(t)
	defer closeExitTarget()

	exitBridge, err := startAgentVPNExitBridge(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-mux",
		Role:      model.VPNRoleExit,
		Extra: map[string]string{
			"bridge_listen": exitTargetAddr,
		},
	}, exitStream)
	if err != nil {
		t.Fatalf("start exit bridge: %v", err)
	}
	defer exitBridge.Close()

	entryAddr := freeLocalTCPAddrForTest(t)
	entryBridge, err := startAgentVPNEntryBridge(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-mux",
		Role:      model.VPNRoleEntry,
		Extra: map[string]string{
			"bridge_addr": entryAddr,
		},
		Limits: model.VPNLimits{
			MaxConnections: 2,
		},
	}, entryStream)
	if err != nil {
		t.Fatalf("start entry bridge: %v", err)
	}
	defer entryBridge.Close()

	first, err := dialEventuallyForTest(entryAddr)
	if err != nil {
		t.Fatalf("dial first entry conn: %v", err)
	}
	defer first.Close()
	second, err := dialEventuallyForTest(entryAddr)
	if err != nil {
		t.Fatalf("dial second entry conn: %v", err)
	}
	defer second.Close()

	firstReply := roundTripVPNBridgeMessage(t, first, "first")
	secondReply := roundTripVPNBridgeMessage(t, second, "second")
	if firstReply != "reply:first" {
		t.Fatalf("first connection response mismatch: %q", firstReply)
	}
	if secondReply != "reply:second" {
		t.Fatalf("second connection response mismatch: %q", secondReply)
	}
}

type scriptedVPNIOStream struct {
	frames  chan *pb.IOStreamData
	err     error
	sendErr error
	sent    chan []byte
	closed  chan struct{}
}

func newBlockingScriptedVPNIOStream() *scriptedVPNIOStream {
	return &scriptedVPNIOStream{
		frames: make(chan *pb.IOStreamData),
		sent:   make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func newScriptedVPNIOStream(frames []*pb.IOStreamData, err error) *scriptedVPNIOStream {
	stream := &scriptedVPNIOStream{
		frames: make(chan *pb.IOStreamData, len(frames)),
		err:    err,
		sent:   make(chan []byte, 16),
		closed: make(chan struct{}),
	}
	for _, frame := range frames {
		stream.frames <- frame
	}
	close(stream.frames)
	return stream
}

func (s *scriptedVPNIOStream) Send(data *pb.IOStreamData) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent <- append([]byte(nil), data.GetData()...)
	return nil
}

func (s *scriptedVPNIOStream) Recv() (*pb.IOStreamData, error) {
	frame, ok := <-s.frames
	if !ok {
		return nil, s.err
	}
	return frame, nil
}

func (s *scriptedVPNIOStream) finish(err error) {
	s.err = err
	close(s.frames)
}

func (s *scriptedVPNIOStream) CloseSend() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func waitForVPNStreamSentFrame(t *testing.T, stream *scriptedVPNIOStream, want string) {
	t.Helper()

	select {
	case got := <-stream.sent:
		if string(got) != want {
			t.Fatalf("stream sent frame mismatch: want %q got %q", want, got)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for stream frame %q", want)
	}
}

func waitForVPNStreamSentMuxPayload(t *testing.T, stream *scriptedVPNIOStream, want string) {
	t.Helper()

	deadline := time.After(time.Second)
	var raw []byte
	for {
		select {
		case got := <-stream.sent:
			raw = append(raw, got...)
			if vpnMuxPayloadExists(raw, want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for mux payload %q", want)
		}
	}
}

func vpnMuxPayloadExists(raw []byte, want string) bool {
	reader := newChunkedReader(raw, 7)
	for {
		frame, err := readVPNMuxFrame(reader)
		if err != nil {
			return false
		}
		if frame.Type == vpnMuxFrameTypeData && string(frame.Payload) == want {
			return true
		}
	}
}

func waitVPNBridgeDone(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bridge returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bridge to stop")
	}
}

func waitVPNBridgeActiveConns(t *testing.T, bridge *AgentVPNBridge, want uint32) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		_, _, got := bridge.stats.Snapshot()
		if got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for active bridge connections: want %d got %d", want, got)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func assertVPNStreamMuxPayloadNotSent(t *testing.T, stream *scriptedVPNIOStream, want string, duration time.Duration) {
	t.Helper()

	timer := time.NewTimer(duration)
	defer timer.Stop()
	var raw []byte
	for {
		select {
		case got := <-stream.sent:
			raw = append(raw, got...)
			if vpnMuxPayloadExists(raw, want) {
				t.Fatalf("unexpected mux payload sent for rejected connection: %q", want)
			}
		case <-timer.C:
			return
		}
	}
}

func waitVPNBridgeFailure(t *testing.T, done <-chan error, want error) {
	t.Helper()

	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("bridge failure mismatch: want %v got %v", want, err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bridge failure")
	}
}

type pairedVPNIOStream struct {
	in       chan *pb.IOStreamData
	peer     *pairedVPNIOStream
	close    chan struct{}
	closeOne sync.Once
}

func newPairedVPNIOStreams() (*pairedVPNIOStream, *pairedVPNIOStream) {
	left := &pairedVPNIOStream{
		in:    make(chan *pb.IOStreamData, 64),
		close: make(chan struct{}),
	}
	right := &pairedVPNIOStream{
		in:    make(chan *pb.IOStreamData, 64),
		close: make(chan struct{}),
	}
	left.peer = right
	right.peer = left
	return left, right
}

func (s *pairedVPNIOStream) Send(data *pb.IOStreamData) error {
	payload := append([]byte(nil), data.GetData()...)
	select {
	case <-s.close:
		return io.ErrClosedPipe
	case <-s.peer.close:
		return io.ErrClosedPipe
	case s.peer.in <- &pb.IOStreamData{Data: payload}:
		return nil
	case <-time.After(time.Second):
		return io.ErrClosedPipe
	}
}

func (s *pairedVPNIOStream) Recv() (*pb.IOStreamData, error) {
	select {
	case data := <-s.in:
		return data, nil
	case <-s.close:
		return nil, io.ErrClosedPipe
	case <-time.After(3 * time.Second):
		return nil, io.ErrClosedPipe
	}
}

func (s *pairedVPNIOStream) CloseSend() error {
	s.closeOne.Do(func() {
		close(s.close)
	})
	return nil
}

func startVPNBridgeEchoTarget(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				_, _ = conn.Write([]byte("reply:" + string(buf[:n])))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func roundTripVPNBridgeMessage(t *testing.T, conn net.Conn, message string) string {
	t.Helper()

	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("write %q: %v", message, err)
	}
	wantPrefix := "reply:" + message
	buf := make([]byte, len(wantPrefix))
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read reply for %q: %v", message, err)
	}
	return strings.TrimSpace(string(buf))
}

func encodeVPNMuxFrameForTest(t *testing.T, frame vpnMuxFrame) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := writeVPNMuxFrame(&buf, frame); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type chunkedReader struct {
	data  []byte
	chunk int
}

func newChunkedReader(data []byte, chunk int) *chunkedReader {
	return &chunkedReader{data: data, chunk: chunk}
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.chunk {
		n = r.chunk
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}
