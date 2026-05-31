package main

import (
	"errors"
	"io"
	"reflect"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

type natErrAfterReader struct {
	chunks [][]byte
	err    error
}

func (r *natErrAfterReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, r.err
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

type recordingNATStream struct {
	frames [][]byte
	closed bool
}

func (s *recordingNATStream) Send(frame *pb.IOStreamData) error {
	s.frames = append(s.frames, append([]byte(nil), frame.Data...))
	return nil
}

func (s *recordingNATStream) CloseSend() error {
	s.closed = true
	return nil
}

func TestForwardNATConnToStreamDoesNotSendReadErrorText(t *testing.T) {
	reader := &natErrAfterReader{
		chunks: [][]byte{{0x00, 0x01, 0x02}},
		err:    errors.New("boom"),
	}
	stream := &recordingNATStream{}

	forwardNATConnToStream(reader, stream, 4)

	if want := [][]byte{{0x00, 0x01, 0x02}}; !reflect.DeepEqual(stream.frames, want) {
		t.Fatalf("frames = %#v, want %#v", stream.frames, want)
	}
	if !stream.closed {
		t.Fatal("expected stream to be closed")
	}
}

func TestForwardNATConnToStreamClosesOnEOFWithoutExtraFrame(t *testing.T) {
	reader := &natErrAfterReader{
		chunks: [][]byte{{0x03}},
		err:    io.EOF,
	}
	stream := &recordingNATStream{}

	forwardNATConnToStream(reader, stream, 4)

	if want := [][]byte{{0x03}}; !reflect.DeepEqual(stream.frames, want) {
		t.Fatalf("frames = %#v, want %#v", stream.frames, want)
	}
	if !stream.closed {
		t.Fatal("expected stream to be closed")
	}
}
