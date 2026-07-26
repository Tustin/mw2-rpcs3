package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	AuthAddr       string
	LobbyAddr      string
	NATAddr        string
	HTTPAddr       string
	LogLevel       string
	CaptureEnabled bool
	CaptureDir     string
	MaxFrameBytes  uint32
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	SessionTTL     time.Duration
	StaticMOTD     string
}

func Load() (Config, error) {
	cfg := Config{
		AuthAddr:      env("MW2_AUTH_ADDR", ":3074"),
		LobbyAddr:     env("MW2_LOBBY_ADDR", ":3075"),
		NATAddr:       env("MW2_NAT_ADDR", ":3076"),
		HTTPAddr:      env("MW2_HTTP_ADDR", ":8080"),
		LogLevel:      env("MW2_LOG_LEVEL", "info"),
		CaptureDir:    env("MW2_CAPTURE_DIR", "captures"),
		StaticMOTD:    env("MW2_MOTD", "MW2 RPCS3 private-match research server"),
		MaxFrameBytes: 1 << 20,
		ReadTimeout:   30 * time.Second,
		WriteTimeout:  10 * time.Second,
		SessionTTL:    2 * time.Minute,
	}

	var err error
	if cfg.CaptureEnabled, err = envBool("MW2_CAPTURE_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.MaxFrameBytes, err = envUint32("MW2_MAX_FRAME_BYTES", cfg.MaxFrameBytes); err != nil {
		return Config{}, err
	}
	if cfg.ReadTimeout, err = envDuration("MW2_READ_TIMEOUT", cfg.ReadTimeout); err != nil {
		return Config{}, err
	}
	if cfg.WriteTimeout, err = envDuration("MW2_WRITE_TIMEOUT", cfg.WriteTimeout); err != nil {
		return Config{}, err
	}
	if cfg.SessionTTL, err = envDuration("MW2_SESSION_TTL", cfg.SessionTTL); err != nil {
		return Config{}, err
	}
	if cfg.MaxFrameBytes < 64 || cfg.MaxFrameBytes > 16<<20 {
		return Config{}, fmt.Errorf("MW2_MAX_FRAME_BYTES must be between 64 and 16777216")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

func envUint32(key string, fallback uint32) (uint32, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return uint32(parsed), nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}
