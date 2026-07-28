package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MW2_AUTH_ADDR", "")
	t.Setenv("MW2_NAT_ADDR", "")
	t.Setenv("MW2_NAT_ALT_ADDR", "")
	t.Setenv("MW2_NAT_ADVERTISED_IP", "")
	t.Setenv("MW2_NAT_RELAY_ENABLED", "")
	t.Setenv("MW2_MAX_FRAME_BYTES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthAddr != ":3074" ||
		cfg.LobbyAddr != ":3075" ||
		cfg.NATAddr != ":3074" ||
		cfg.NATAlternateAddr != ":3075" ||
		cfg.NATAdvertisedIP != "" ||
		cfg.NATRelayEnabled ||
		cfg.MaxFrameBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadNATAddressOverride(t *testing.T) {
	t.Setenv("MW2_NAT_ADDR", "127.0.0.1:43074")
	t.Setenv("MW2_NAT_ALT_ADDR", "127.0.0.1:43075")
	t.Setenv("MW2_NAT_ADVERTISED_IP", "192.0.2.25")
	t.Setenv("MW2_NAT_RELAY_ENABLED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NATAddr != "127.0.0.1:43074" {
		t.Fatalf("NATAddr = %q, want explicit override", cfg.NATAddr)
	}
	if cfg.NATAlternateAddr != "127.0.0.1:43075" {
		t.Fatalf("NATAlternateAddr = %q, want explicit override", cfg.NATAlternateAddr)
	}
	if cfg.NATAdvertisedIP != "192.0.2.25" {
		t.Fatalf("NATAdvertisedIP = %q, want explicit override", cfg.NATAdvertisedIP)
	}
	if !cfg.NATRelayEnabled {
		t.Fatal("NATRelayEnabled = false, want explicit true")
	}
}

func TestLoadRejectsInvalidNATAdvertisedIP(t *testing.T) {
	for _, value := range []string{
		"not-an-ip",
		"2001:db8::1",
		"0.0.0.0",
		"224.0.0.1",
		"255.255.255.255",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("MW2_NAT_ADVERTISED_IP", value)
			if _, err := Load(); err == nil {
				t.Fatalf("accepted unusable advertised IP %q", value)
			}
		})
	}
}

func TestLoadRejectsMatchingNATPorts(t *testing.T) {
	t.Setenv("MW2_NAT_ADDR", "127.0.0.1:43074")
	t.Setenv("MW2_NAT_ALT_ADDR", "0.0.0.0:43074")
	if _, err := Load(); err == nil {
		t.Fatal("accepted matching primary and alternate UDP ports")
	}
}

func TestLoadRejectsInvalidNATRelayFlag(t *testing.T) {
	t.Setenv("MW2_NAT_RELAY_ENABLED", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("accepted invalid MW2_NAT_RELAY_ENABLED")
	}
}

func TestLoadRejectsInvalidLimit(t *testing.T) {
	t.Setenv("MW2_MAX_FRAME_BYTES", "32")
	if _, err := Load(); err == nil {
		t.Fatal("expected validation error")
	}
}
