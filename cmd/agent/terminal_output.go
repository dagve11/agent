package main

import (
	"time"

	pb "github.com/nezhahq/agent/proto"
)

const (
	terminalOutputReadBufferSize = 16 * 1024
	terminalOutputMaxBatchBytes  = 32 * 1024
	terminalOutputFlushInterval  = 8 * time.Millisecond
)

type terminalOutputReader interface {
	Read([]byte) (int, error)
}

type terminalOutputChunk struct {
	data []byte
	err  error
}

func forwardTerminalOutput(reader terminalOutputReader, sender ioStreamSender, flushInterval time.Duration, maxBatchBytes int) error {
	if flushInterval <= 0 {
		flushInterval = terminalOutputFlushInterval
	}
	if maxBatchBytes <= 0 {
		maxBatchBytes = terminalOutputMaxBatchBytes
	}

	chunks := make(chan terminalOutputChunk, 32)
	done := make(chan struct{})
	defer close(done)
	go readTerminalOutputChunks(reader, chunks, done)

	pending := make([]byte, 0, minInt(maxBatchBytes, terminalOutputReadBufferSize))
	var flushTimer *time.Timer
	var flushTimerC <-chan time.Time

	stopTimer := func() {
		if flushTimer == nil {
			return
		}
		if !flushTimer.Stop() {
			select {
			case <-flushTimer.C:
			default:
			}
		}
		flushTimer = nil
		flushTimerC = nil
	}
	startTimer := func() {
		if flushTimer != nil {
			return
		}
		flushTimer = time.NewTimer(flushInterval)
		flushTimerC = flushTimer.C
	}
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		err := sender.Send(&pb.IOStreamData{Data: pending})
		pending = pending[:0]
		return err
	}
	appendChunk := func(data []byte) error {
		for len(data) > 0 {
			if len(pending) == 0 {
				startTimer()
			}

			space := maxBatchBytes - len(pending)
			take := minInt(len(data), space)
			pending = append(pending, data[:take]...)
			data = data[take:]

			if len(pending) >= maxBatchBytes {
				stopTimer()
				if err := flush(); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				stopTimer()
				return flush()
			}
			if len(chunk.data) > 0 {
				if err := appendChunk(chunk.data); err != nil {
					stopTimer()
					return err
				}
			}
			if chunk.err != nil {
				stopTimer()
				if err := flush(); err != nil {
					return err
				}
				if err := sender.Send(&pb.IOStreamData{Data: []byte(chunk.err.Error())}); err != nil {
					return err
				}
				return chunk.err
			}
		case <-flushTimerC:
			flushTimer = nil
			flushTimerC = nil
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

func readTerminalOutputChunks(reader terminalOutputReader, chunks chan<- terminalOutputChunk, done <-chan struct{}) {
	defer close(chunks)

	buf := make([]byte, terminalOutputReadBufferSize)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if !sendTerminalOutputChunk(chunks, done, terminalOutputChunk{data: append([]byte(nil), buf[:n]...)}) {
				return
			}
		}
		if err != nil {
			_ = sendTerminalOutputChunk(chunks, done, terminalOutputChunk{err: err})
			return
		}
	}
}

func sendTerminalOutputChunk(chunks chan<- terminalOutputChunk, done <-chan struct{}, chunk terminalOutputChunk) bool {
	select {
	case chunks <- chunk:
		return true
	case <-done:
		return false
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
