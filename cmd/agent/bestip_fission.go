package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/bestip"
	pb "github.com/nezhahq/agent/proto"
)

func handleBestIPFissionTask(task *pb.Task, send func(*pb.TaskResult) error, cancelStream context.CancelFunc) {
	taskCtx, cancelTask := context.WithCancel(context.Background())
	defer cancelTask()

	var sendFailed atomic.Bool
	sendPayload := func(success bool, payload model.BestIPFissionTaskResult) bool {
		if sendFailed.Load() {
			return false
		}
		data, err := json.Marshal(payload)
		if err != nil {
			payload = model.BestIPFissionTaskResult{
				Kind:  model.BestIPFissionTaskResultError,
				Error: err.Error(),
			}
			data, _ = json.Marshal(payload)
			success = false
		}
		if err := send(&pb.TaskResult{
			Id:         task.GetId(),
			Type:       model.TaskTypeBestIPFission,
			Successful: success,
			Data:       string(data),
		}); err != nil {
			printf("send bestip fission task result exit: %v", err)
			sendFailed.Store(true)
			cancelTask()
			cancelStream()
			return false
		}
		return true
	}
	sendError := func(err error) {
		if err == nil {
			err = fmt.Errorf("bestip fission failed")
		}
		sendPayload(false, model.BestIPFissionTaskResult{
			Kind:  model.BestIPFissionTaskResultError,
			Error: err.Error(),
		})
	}

	var req model.BestIPFissionTaskRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		sendError(err)
		return
	}
	config := req.Config
	config.ProbeServerID = 0
	config, err := bestip.NormalizeFissionConfig(config)
	if err != nil {
		sendError(err)
		return
	}

	service := bestip.NewFissionService(config)
	service.Progress = func(event bestip.FissionProgressEvent) {
		eventCopy := event
		sendPayload(true, model.BestIPFissionTaskResult{
			Kind:  model.BestIPFissionTaskResultProgress,
			Event: &eventCopy,
		})
	}

	result, err := service.Run(taskCtx)
	if sendFailed.Load() {
		return
	}
	if err != nil {
		sendError(err)
		return
	}
	sendPayload(true, model.BestIPFissionTaskResult{
		Kind:   model.BestIPFissionTaskResultDone,
		Result: result,
	})
}
