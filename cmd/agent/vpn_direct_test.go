package main

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestAgentVPNDirectRelayTransfersFrames(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	entryStream, err := manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-session",
		Role:      model.VPNRoleEntry,
		Token:     "session-token",
		Extra: map[string]string{
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_cert_sha256": cfg.VPNDirectCertSHA256,
		},
	})
	if err != nil {
		t.Fatalf("dial direct exit: %v", err)
	}
	defer entryStream.CloseSend()
	defer exitStream.CloseSend()

	if err := entryStream.Send(&pb.IOStreamData{Data: []byte("entry-to-exit")}); err != nil {
		t.Fatalf("send entry frame: %v", err)
	}
	got, err := exitStream.Recv()
	if err != nil {
		t.Fatalf("recv exit frame: %v", err)
	}
	if string(got.GetData()) != "entry-to-exit" {
		t.Fatalf("exit frame = %q", got.GetData())
	}

	if err := exitStream.Send(&pb.IOStreamData{Data: []byte("exit-to-entry")}); err != nil {
		t.Fatalf("send exit frame: %v", err)
	}
	got, err = entryStream.Recv()
	if err != nil {
		t.Fatalf("recv entry frame: %v", err)
	}
	if string(got.GetData()) != "exit-to-entry" {
		t.Fatalf("entry frame = %q", got.GetData())
	}
}

func TestAgentVPNDirectRelayRejectsCertificateMismatch(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	_, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	_, err = manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-session",
		Role:      model.VPNRoleEntry,
		Token:     "session-token",
		Extra: map[string]string{
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_cert_sha256": strings.Repeat("0", 64),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
}

func TestAgentVPNDirectRelayRejectsInvalidToken(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	defer exitStream.CloseSend()

	_, err = manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-session",
		Role:      model.VPNRoleEntry,
		Token:     "wrong-token",
		Extra: map[string]string{
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_cert_sha256": cfg.VPNDirectCertSHA256,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid VPN direct session token") {
		t.Fatalf("expected invalid token rejection, got %v", err)
	}
}

func TestAgentVPNDirectWSTLSTransfersEncryptedFrames(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-ws-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
		Extra: map[string]string{
			"direct_transport": model.VPNDirectTransportWSTLS,
			"direct_crypto":    model.VPNDirectCryptoV2,
			"direct_ws_path":   "/pt/test",
		},
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	entryStream, err := manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-ws-session",
		Role:      model.VPNRoleEntry,
		Token:     "session-token",
		Extra: map[string]string{
			"direct_transport":   model.VPNDirectTransportWSTLS,
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_ws_path":     "/pt/test",
			"direct_tls_verify":  "false",
			"direct_cert_sha256": cfg.VPNDirectCertSHA256,
		},
	})
	if err != nil {
		t.Fatalf("dial direct websocket exit: %v", err)
	}
	defer entryStream.CloseSend()
	defer exitStream.CloseSend()

	if err := entryStream.Send(&pb.IOStreamData{Data: []byte("entry-to-exit")}); err != nil {
		t.Fatalf("send entry frame: %v", err)
	}
	got, err := exitStream.Recv()
	if err != nil {
		t.Fatalf("recv exit frame: %v", err)
	}
	if string(got.GetData()) != "entry-to-exit" {
		t.Fatalf("exit frame = %q", got.GetData())
	}

	if err := exitStream.Send(&pb.IOStreamData{Data: []byte("exit-to-entry")}); err != nil {
		t.Fatalf("send exit frame: %v", err)
	}
	got, err = entryStream.Recv()
	if err != nil {
		t.Fatalf("recv entry frame: %v", err)
	}
	if string(got.GetData()) != "exit-to-entry" {
		t.Fatalf("entry frame = %q", got.GetData())
	}
}

func TestAgentVPNDirectWSTLSAllowsMaxPlaintextFrame(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-ws-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
		Extra: map[string]string{
			"direct_transport": model.VPNDirectTransportWSTLS,
			"direct_crypto":    model.VPNDirectCryptoV2,
			"direct_ws_path":   "/pt/test",
		},
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	entryStream, err := manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-ws-session",
		Role:      model.VPNRoleEntry,
		Token:     "session-token",
		Extra: map[string]string{
			"direct_transport":   model.VPNDirectTransportWSTLS,
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_ws_path":     "/pt/test",
			"direct_tls_verify":  "false",
			"direct_cert_sha256": cfg.VPNDirectCertSHA256,
		},
	})
	if err != nil {
		t.Fatalf("dial direct websocket exit: %v", err)
	}
	defer entryStream.CloseSend()
	defer exitStream.CloseSend()

	payload := make([]byte, vpnDirectMaxFrameSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- entryStream.Send(&pb.IOStreamData{Data: payload})
	}()
	got, err := exitStream.Recv()
	if err != nil {
		t.Fatalf("recv max plaintext frame: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("send max plaintext frame: %v", err)
	}
	if !bytes.Equal(got.GetData(), payload) {
		t.Fatalf("max plaintext frame mismatch: got=%d want=%d", len(got.GetData()), len(payload))
	}
}

func TestAgentVPNDirectWSTLSRejectsInvalidToken(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-ws-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
		Extra: map[string]string{
			"direct_transport": model.VPNDirectTransportWSTLS,
			"direct_crypto":    model.VPNDirectCryptoV2,
			"direct_ws_path":   "/pt/test",
		},
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	defer exitStream.CloseSend()

	_, err = manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-ws-session",
		Role:      model.VPNRoleEntry,
		Token:     "wrong-token",
		Extra: map[string]string{
			"direct_transport":   model.VPNDirectTransportWSTLS,
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_ws_path":     "/pt/test",
			"direct_tls_verify":  "false",
			"direct_cert_sha256": cfg.VPNDirectCertSHA256,
		},
	})
	if err == nil {
		t.Fatal("expected invalid websocket token rejection")
	}
}

func TestAgentVPNDirectWSTLSRejectsInsecureWithoutCertificatePin(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-ws-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
		Extra: map[string]string{
			"direct_transport": model.VPNDirectTransportWSTLS,
			"direct_crypto":    model.VPNDirectCryptoV2,
			"direct_ws_path":   "/pt/test",
		},
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	defer exitStream.CloseSend()

	_, err = manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-ws-session",
		Role:      model.VPNRoleEntry,
		Token:     "session-token",
		Extra: map[string]string{
			"direct_transport":  model.VPNDirectTransportWSTLS,
			"direct_address":    "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_ws_path":    "/pt/test",
			"direct_tls_verify": "false",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "direct_cert_sha256 is required") {
		t.Fatalf("expected missing certificate pin rejection, got %v", err)
	}
}

func TestAgentVPNDirectWSTLSRejectsMismatchedPath(t *testing.T) {
	manager, cfg := newTestVPNDirectManager(t)
	exitStream, err := manager.Register(model.VPNControlRequest{
		SessionID:     "vpn-direct-ws-session",
		Role:          model.VPNRoleExit,
		RelayMode:     model.VPNRelayModeDirect,
		Token:         "session-token",
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
		Extra: map[string]string{
			"direct_transport": model.VPNDirectTransportWSTLS,
			"direct_crypto":    model.VPNDirectCryptoV2,
			"direct_ws_path":   "/pt/expected",
		},
	})
	if err != nil {
		t.Fatalf("register direct exit: %v", err)
	}
	defer exitStream.CloseSend()

	_, err = manager.Dial(context.Background(), model.VPNControlRequest{
		SessionID: "vpn-direct-ws-session",
		Role:      model.VPNRoleEntry,
		Token:     "session-token",
		Extra: map[string]string{
			"direct_transport":   model.VPNDirectTransportWSTLS,
			"direct_address":     "127.0.0.1:" + strconv.Itoa(int(cfg.VPNDirectListenPort)),
			"direct_ws_path":     "/pt/wrong",
			"direct_tls_verify":  "false",
			"direct_cert_sha256": cfg.VPNDirectCertSHA256,
		},
	})
	if err == nil {
		t.Fatal("expected mismatched websocket path rejection")
	}
}

func TestVPNDirectEncryptedControlFrameHidesHandshakeMetadata(t *testing.T) {
	hello := vpnDirectV2Hello{
		Version:   vpnDirectV2Version,
		SessionID: "vpn-direct-ws-session",
		Timestamp: time.Now().Unix(),
		Nonce:     strings.Repeat("a", 32),
		Transport: model.VPNDirectTransportWSTLS,
		Crypto:    model.VPNDirectCryptoV2,
	}
	hello.MAC = vpnDirectV2HelloMAC("session-token", hello)
	frame, err := sealVPNDirectEncryptedControlFrame("session-token", hello.SessionID, "/pt/test", "hello", hello)
	if err != nil {
		t.Fatalf("seal control frame: %v", err)
	}
	for _, marker := range [][]byte{[]byte("session-token"), []byte(hello.SessionID), []byte("/pt/test"), []byte("session_id")} {
		if bytes.Contains(frame, marker) {
			t.Fatalf("encrypted control frame leaked marker %q", marker)
		}
	}
	var decoded vpnDirectV2Hello
	if err := openVPNDirectEncryptedControlFrame("session-token", hello.SessionID, "/pt/test", "hello", frame, &decoded); err != nil {
		t.Fatalf("open control frame: %v", err)
	}
	if decoded.SessionID != hello.SessionID || decoded.MAC != hello.MAC {
		t.Fatalf("decoded hello mismatch: %#v", decoded)
	}
}

func newTestVPNDirectManager(t *testing.T) (*AgentVPNDirectManager, *model.AgentConfig) {
	t.Helper()
	originalConfig := agentConfig
	t.Cleanup(func() { agentConfig = originalConfig })
	agentConfig = model.AgentConfig{VPNStateDir: t.TempDir()}
	cfg := &model.AgentConfig{
		VPNDirectEnabled: true,
		VPNDirectListen:  "127.0.0.1:0",
		VPNStateDir:      agentConfig.VPNStateDir,
	}
	manager := NewAgentVPNDirectManager()
	if err := manager.Start(cfg); err != nil {
		t.Fatalf("start direct manager: %v", err)
	}
	t.Cleanup(func() {
		manager.mu.Lock()
		if manager.listener != nil {
			_ = manager.listener.Close()
		}
		manager.mu.Unlock()
	})
	return manager, cfg
}
