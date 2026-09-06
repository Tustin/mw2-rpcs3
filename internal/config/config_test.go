package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MW2_AUTH_ADDR", "")
	t.Setenv("MW2_NAT_ADDR", "")
	t.Setenv("MW2_NAT_ALT_ADDR", "")
	t.Setenv("MW2_NAT_ADVERTISED_IP", "")
	t.Setenv("MW2_NAT_RELAY_ENABLED", "")
	t.Setenv("MW2_MATCHMAKING_SUPPRESS_SELF_ONLY", "")
	t.Setenv("MW2_MATCHMAKING_PREFER_EARLIER_HOSTS", "")
	t.Setenv("MW2_LOG_SENSITIVE", "")
	t.Setenv("MW2_MAX_FRAME_BYTES", "")
	t.Setenv("MW2_BANDWIDTH_SEND_DURATION_MS", "")
	t.Setenv("MW2_BANDWIDTH_FINALIZE_RECEIVE_PERIOD_MS", "")
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
		cfg.SuppressSelfOnly ||
		cfg.PreferEarlierHosts ||
		cfg.LogSensitive ||
		cfg.MaxFrameBytes != 1<<20 ||
		cfg.BandwidthSendDurationMS != 50 ||
		cfg.BandwidthFinalizeReceivePeriodMS != nil {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadSensitiveLoggingOverride(t *testing.T) {
	t.Setenv("MW2_LOG_SENSITIVE", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LogSensitive {
		t.Fatal("LogSensitive = false, want explicit true")
	}
}

func TestLoadRejectsInvalidSensitiveLoggingFlag(t *testing.T) {
	t.Setenv("MW2_LOG_SENSITIVE", "all")
	if _, err := Load(); err == nil {
		t.Fatal("accepted invalid MW2_LOG_SENSITIVE")
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

func TestLoadSuppressSelfOnlyOverride(t *testing.T) {
	t.Setenv("MW2_MATCHMAKING_SUPPRESS_SELF_ONLY", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SuppressSelfOnly {
		t.Fatal("SuppressSelfOnly = false, want explicit true")
	}
}

func TestLoadRejectsInvalidSuppressSelfOnlyFlag(t *testing.T) {
	t.Setenv("MW2_MATCHMAKING_SUPPRESS_SELF_ONLY", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("accepted invalid MW2_MATCHMAKING_SUPPRESS_SELF_ONLY")
	}
}

func TestLoadPreferEarlierHostsOverride(t *testing.T) {
	t.Setenv("MW2_MATCHMAKING_PREFER_EARLIER_HOSTS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PreferEarlierHosts {
		t.Fatal("PreferEarlierHosts = false, want explicit true")
	}
}

func TestLoadRejectsInvalidPreferEarlierHostsFlag(t *testing.T) {
	t.Setenv("MW2_MATCHMAKING_PREFER_EARLIER_HOSTS", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("accepted invalid MW2_MATCHMAKING_PREFER_EARLIER_HOSTS")
	}
}

func TestLoadBandwidthExperimentOverrides(t *testing.T) {
	t.Setenv("MW2_BANDWIDTH_SEND_DURATION_MS", "50")
	t.Setenv("MW2_BANDWIDTH_FINALIZE_RECEIVE_PERIOD_MS", "40")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BandwidthSendDurationMS != 50 {
		t.Fatalf("BandwidthSendDurationMS = %d, want 50", cfg.BandwidthSendDurationMS)
	}
	if cfg.BandwidthFinalizeReceivePeriodMS == nil || *cfg.BandwidthFinalizeReceivePeriodMS != 40 {
		t.Fatalf("BandwidthFinalizeReceivePeriodMS = %v, want 40", cfg.BandwidthFinalizeReceivePeriodMS)
	}
}

func TestLoadRejectsInvalidBandwidthExperimentOverride(t *testing.T) {
	t.Setenv("MW2_BANDWIDTH_FINALIZE_RECEIVE_PERIOD_MS", "forty")
	if _, err := Load(); err == nil {
		t.Fatal("accepted invalid MW2_BANDWIDTH_FINALIZE_RECEIVE_PERIOD_MS")
	}
}

func TestLoadRejectsInvalidLimit(t *testing.T) {
	t.Setenv("MW2_MAX_FRAME_BYTES", "32")
	if _, err := Load(); err == nil {
		t.Fatal("expected validation error")
	}
}
