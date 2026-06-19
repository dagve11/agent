package main

import (
	"context"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestSerialAgentTaskDispatcherRunsTasksInArrivalOrder(t *testing.T) {
	started := make(chan uint64, 2)
	done := make(chan uint64, 2)
	releaseFirst := make(chan struct{})

	dispatcher := newSerialAgentTaskDispatcher(func(task *pb.Task, _ func(*pb.TaskResult) error, _ context.CancelFunc) {
		started <- task.GetId()
		if task.GetId() == 1 {
			<-releaseFirst
		}
		done <- task.GetId()
	})

	dispatcher.Dispatch(&pb.Task{Id: 1}, nil, nil)
	if got := <-started; got != 1 {
		t.Fatalf("first task started = %d, want 1", got)
	}
	dispatcher.Dispatch(&pb.Task{Id: 2}, nil, nil)

	select {
	case got := <-started:
		t.Fatalf("second task started before first completed: %d", got)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)
	if got := <-done; got != 1 {
		t.Fatalf("first completed task = %d, want 1", got)
	}
	if got := <-started; got != 2 {
		t.Fatalf("second started task = %d, want 2", got)
	}
	if got := <-done; got != 2 {
		t.Fatalf("second completed task = %d, want 2", got)
	}
}
