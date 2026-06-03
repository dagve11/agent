package main

import (
	"io"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type scriptedTerminalReader struct {
	reads [][]byte
	idx   int
}

func (r *scriptedTerminalReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.reads) {
		return 0, io.EOF
	}
	n := copy(p, r.reads[r.idx])
	r.idx++
	return n, nil
}

type recordingTerminalSender struct {
	frames [][]byte
}

func (s *recordingTerminalSender) Send(d *pb.IOStreamData) error {
	s.frames = append(s.frames, append([]byte(nil), d.Data...))
	return nil
}

func TestForwardTerminalOutputCoalescesSmallChunks(t *testing.T) {
	reader := &scriptedTerminalReader{
		reads: [][]byte{
			[]byte("he"),
			[]byte("ll"),
			[]byte("o"),
		},
	}
	sender := &recordingTerminalSender{}

	err := forwardTerminalOutput(reader, sender, time.Hour, 1024)
	if err != io.EOF {
		t.Fatalf("forwardTerminalOutput err = %v, want io.EOF", err)
	}
	if len(sender.frames) < 1 {
		t.Fatal("expected at least one output frame")
	}
	if got := string(sender.frames[0]); got != "hello" {
		t.Fatalf("first frame = %q, want hello", got)
	}
}

func TestForwardTerminalOutputFlushesWhenBatchLimitIsReached(t *testing.T) {
	reader := &scriptedTerminalReader{
		reads: [][]byte{
			[]byte("abc"),
			[]byte("def"),
			[]byte("ghi"),
		},
	}
	sender := &recordingTerminalSender{}

	err := forwardTerminalOutput(reader, sender, time.Hour, 6)
	if err != io.EOF {
		t.Fatalf("forwardTerminalOutput err = %v, want io.EOF", err)
	}
	if len(sender.frames) < 2 {
		t.Fatalf("expected at least two output frames, got %d", len(sender.frames))
	}
	if got := string(sender.frames[0]); got != "abcdef" {
		t.Fatalf("first frame = %q, want abcdef", got)
	}
	if got := string(sender.frames[1]); got != "ghi" {
		t.Fatalf("second frame = %q, want ghi", got)
	}
}
