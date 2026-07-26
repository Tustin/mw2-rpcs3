package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MW2_AUTH_ADDR", "")
	t.Setenv("MW2_MAX_FRAME_BYTES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthAddr != ":3074" || cfg.LobbyAddr != ":3075" || cfg.MaxFrameBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsInvalidLimit(t *testing.T) {
	t.Setenv("MW2_MAX_FRAME_BYTES", "32")
	if _, err := Load(); err == nil {
		t.Fatal("expected validation error")
	}
}
