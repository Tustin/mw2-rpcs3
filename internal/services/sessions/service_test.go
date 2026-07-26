package sessions

import (
	"context"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/protocol"
)

func TestSessionLifecycle(t *testing.T) {
	service := New(time.Minute)
	dispatcher := protocol.NewDispatcher()
	if err := service.Register(dispatcher); err != nil {
		t.Fatal(err)
	}
	create := createRequest("room", 10, "192.0.2.1:3074", 2)
	if response, err := dispatcher.Dispatch(context.Background(), create); err != nil || response.Kind != protocol.KindResponse {
		t.Fatalf("create: %v %#v", err, response)
	}
	join := stringUintRequest(TaskJoin, "room", 11)
	if response, err := dispatcher.Dispatch(context.Background(), join); err != nil || response.Kind != protocol.KindResponse {
		t.Fatalf("join: %v %#v", err, response)
	}
	full := stringUintRequest(TaskJoin, "room", 12)
	if response, err := dispatcher.Dispatch(context.Background(), full); err == nil || response.Kind != protocol.KindError {
		t.Fatalf("expected full: %v %#v", err, response)
	}
	leave := stringUintRequest(TaskLeave, "room", 10)
	if _, err := dispatcher.Dispatch(context.Background(), leave); err != nil {
		t.Fatal(err)
	}
	find := protocol.Frame{Kind: protocol.KindRequest, Service: ServiceID, Task: TaskFind, Transaction: 5}
	response, err := dispatcher.Dispatch(context.Background(), find)
	if err != nil {
		t.Fatal(err)
	}
	decoder := protocol.NewDecoder(response.Payload, 1024)
	count, _ := decoder.Uint16()
	if count != 0 {
		t.Fatalf("count=%d", count)
	}
}

func TestStaleCleanup(t *testing.T) {
	service := New(time.Second)
	now := time.Unix(100, 0)
	service.now = func() time.Time { return now }
	dispatcher := protocol.NewDispatcher()
	_ = service.Register(dispatcher)
	_, _ = dispatcher.Dispatch(context.Background(), createRequest("stale", 1, "127.0.0.1:1", 2))
	now = now.Add(2 * time.Second)
	response, _ := dispatcher.Dispatch(context.Background(), protocol.Frame{Kind: protocol.KindRequest, Service: ServiceID, Task: TaskFind})
	decoder := protocol.NewDecoder(response.Payload, 1024)
	count, _ := decoder.Uint16()
	if count != 0 {
		t.Fatalf("count=%d", count)
	}
}

func createRequest(id string, host uint64, address string, capacity uint16) protocol.Frame {
	var enc protocol.Encoder
	enc.String(id)
	enc.Uint64(host)
	enc.String(address)
	enc.Uint16(capacity)
	enc.Bytes([]byte("join"))
	return protocol.Frame{Kind: protocol.KindRequest, Service: ServiceID, Task: TaskCreate, Transaction: 1, Payload: enc.Data()}
}
func stringUintRequest(task uint8, value string, number uint64) protocol.Frame {
	var enc protocol.Encoder
	enc.String(value)
	enc.Uint64(number)
	return protocol.Frame{Kind: protocol.KindRequest, Service: ServiceID, Task: task, Transaction: 2, Payload: enc.Data()}
}
