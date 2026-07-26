package integration

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/auth"
	"github.com/josh/mw2-rpcs3/internal/protocol"
	"github.com/josh/mw2-rpcs3/internal/services/sessions"
	"github.com/josh/mw2-rpcs3/internal/services/storage"
)

func TestCoreServices(t *testing.T) {
	dispatcher := protocol.NewDispatcher()
	authService, err := auth.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, register := range []func(*protocol.Dispatcher) error{authService.Register, storage.New("hello").Register, sessions.New(time.Minute).Register} {
		if err := register(dispatcher); err != nil {
			t.Fatal(err)
		}
	}
	var login protocol.Encoder
	login.String("rpcn-user")
	login.String("BLUS30377-1.14")
	response, err := dispatcher.Dispatch(context.Background(), protocol.Frame{Kind: protocol.KindRequest, Service: auth.ServiceID, Task: auth.TaskLogin, Transaction: 9, Payload: login.Data()})
	if err != nil || response.Kind != protocol.KindResponse || response.Transaction != 9 {
		t.Fatalf("login: %v %#v", err, response)
	}
	var get protocol.Encoder
	get.String("motd")
	response, err = dispatcher.Dispatch(context.Background(), protocol.Frame{Kind: protocol.KindRequest, Service: storage.ServiceID, Task: storage.TaskGet, Payload: get.Data()})
	if err != nil || !bytes.Contains(response.Payload, []byte("hello")) {
		t.Fatalf("storage: %v %x", err, response.Payload)
	}
	response, err = dispatcher.Dispatch(context.Background(), protocol.Frame{Kind: protocol.KindRequest, Service: 255, Task: 255})
	if err == nil || response.Kind != protocol.KindError {
		t.Fatal("unknown task should return an error frame")
	}
}
