package auth

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

func TestAdminProfileLifecycle(t *testing.T) {
	server := NewRawServer("", slog.New(slog.NewTextHandler(io.Discard, nil)), capture.New(false, "", RetailRequestSize), time.Second, time.Second)
	defer server.userFiles.close()
	data := bytes.Repeat([]byte{0x11}, mw2ProfileSize)
	file, err := server.userFiles.upload(0xffffffffffffffff, mw2ProfileFilename, data)
	if err != nil {
		t.Fatal(err)
	}

	profiles, err := server.AdminProfiles(context.Background(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].OwnerID != "18446744073709551615" || profiles[0].FileID != "1" || profiles[0].Size != mw2ProfileSize {
		t.Fatalf("profiles = %+v", profiles)
	}

	profile, ok, err := server.AdminProfile(context.Background(), file.id)
	if err != nil || !ok || !bytes.Equal(profile.Data, data) {
		t.Fatalf("profile = %+v, ok = %v, err = %v", profile, ok, err)
	}

	updated := bytes.Repeat([]byte{0x22}, mw2ProfileSize)
	profile, ok, err = server.AdminUpdateProfile(context.Background(), file.id, updated)
	if err != nil || !ok || !bytes.Equal(profile.Data, updated) {
		t.Fatalf("updated profile = %+v, ok = %v, err = %v", profile, ok, err)
	}

	deleted, err := server.AdminDeleteProfile(context.Background(), file.id)
	if err != nil || !deleted {
		t.Fatalf("deleted = %v, err = %v", deleted, err)
	}
	if _, ok, err := server.AdminProfile(context.Background(), file.id); err != nil || ok {
		t.Fatalf("profile remained after delete: ok = %v, err = %v", ok, err)
	}
}

func TestAdminUpdateProfileRejectsWrongSize(t *testing.T) {
	server := NewRawServer("", slog.New(slog.NewTextHandler(io.Discard, nil)), capture.New(false, "", RetailRequestSize), time.Second, time.Second)
	defer server.userFiles.close()
	if _, _, err := server.AdminUpdateProfile(context.Background(), 1, []byte("short")); err == nil {
		t.Fatal("accepted wrong profile size")
	}
}
