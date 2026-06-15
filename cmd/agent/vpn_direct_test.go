package main

import (
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
