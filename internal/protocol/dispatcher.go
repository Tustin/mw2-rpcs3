package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

var ErrUnknownTask = errors.New("unknown service or task")

type Handler func(context.Context, Frame) (Frame, error)

type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[uint16]Handler
}

func NewDispatcher() *Dispatcher { return &Dispatcher{handlers: make(map[uint16]Handler)} }

func taskKey(service, task uint8) uint16 { return uint16(service)<<8 | uint16(task) }

func (d *Dispatcher) Register(service, task uint8, handler Handler) error {
	if handler == nil {
		return errors.New("nil handler")
	}
	key := taskKey(service, task)
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.handlers[key]; exists {
		return fmt.Errorf("handler already registered for %d/%d", service, task)
	}
	d.handlers[key] = handler
	return nil
}

func (d *Dispatcher) Dispatch(ctx context.Context, request Frame) (Frame, error) {
	d.mu.RLock()
	handler := d.handlers[taskKey(request.Service, request.Task)]
	d.mu.RUnlock()
	if handler == nil {
		payload, _ := json.Marshal(map[string]any{"code": "unknown_task", "service": request.Service, "task": request.Task})
		return Frame{Kind: KindError, Service: request.Service, Task: request.Task, Transaction: request.Transaction, Payload: payload}, ErrUnknownTask
	}
	response, err := handler(ctx, request)
	response.Service = request.Service
	response.Task = request.Task
	response.Transaction = request.Transaction
	if response.Kind == 0 {
		response.Kind = KindResponse
	}
	return response, err
}
