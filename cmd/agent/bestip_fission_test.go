package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestHandleBestIPFissionTaskRejectsInvalidConfig(t *testing.T) {
	body, err := json.Marshal(model.BestIPFissionTaskRequest{})
	if err != nil {
		t.Fatal(err)
	}

	results := make(chan *pb.TaskResult, 1)
	handleBestIPFissionTask(&pb.Task{
		Id:   99,
		Type: model.TaskTypeBestIPFission,
		Data: string(body),
	}, func(result *pb.TaskResult) error {
		results <- result
		return nil
	}, func() {})

	select {
	case result := <-results:
		if result.GetId() != 99 || result.GetType() != model.TaskTypeBestIPFission {
			t.Fatalf("unexpected task result identity: id=%d type=%d", result.GetId(), result.GetType())
		}
		if result.GetSuccessful() {
			t.Fatal("invalid BestIP config must report unsuccessful result")
		}
		var payload model.BestIPFissionTaskResult
		if err := json.Unmarshal([]byte(result.GetData()), &payload); err != nil {
			t.Fatalf("invalid result payload: %v", err)
		}
		if payload.Kind != model.BestIPFissionTaskResultError || payload.Error == "" {
			t.Fatalf("expected error payload, got %+v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for BestIP fission task result")
	}
}
