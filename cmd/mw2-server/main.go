package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/josh/mw2-rpcs3/internal/admin"
	"github.com/josh/mw2-rpcs3/internal/auth"
	"github.com/josh/mw2-rpcs3/internal/bandwidth"
	"github.com/josh/mw2-rpcs3/internal/capture"
	"github.com/josh/mw2-rpcs3/internal/config"
	"github.com/josh/mw2-rpcs3/internal/health"
	"github.com/josh/mw2-rpcs3/internal/protocol"
	"github.com/josh/mw2-rpcs3/internal/server"
	"github.com/josh/mw2-rpcs3/internal/services/nat"
	"github.com/josh/mw2-rpcs3/internal/services/sessions"
	"github.com/josh/mw2-rpcs3/internal/services/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	dispatcher := protocol.NewDispatcher()
	authService, err := auth.New()
	if err != nil {
		logger.Error("auth initialization failed", "error", err)
		os.Exit(1)
	}
	for _, register := range []func(*protocol.Dispatcher) error{authService.Register, storage.New(cfg.StaticMOTD).Register, sessions.New(cfg.SessionTTL).Register} {
		if err := register(dispatcher); err != nil {
			logger.Error("service registration failed", "error", err)
			os.Exit(1)
		}
	}
	recorder := capture.New(cfg.CaptureEnabled, cfg.CaptureDir, int(cfg.MaxFrameBytes))
	authServer := auth.NewRawServer(cfg.AuthAddr, logger, recorder, cfg.ReadTimeout, cfg.WriteTimeout)
	authServer.SetSensitiveLogging(cfg.LogSensitive)
	authServer.SetMatchmakingSuppressSelfOnly(cfg.SuppressSelfOnly)
	authServer.SetMatchmakingPreferEarlierHosts(cfg.PreferEarlierHosts)
	if err := authServer.SetStatsDatabase(cfg.StatsDBPath); err != nil {
		logger.Error("stats database initialization failed", "error", err)
		os.Exit(1)
	}
	if err := authServer.SetProfileDatabase(cfg.ProfileDBPath); err != nil {
		logger.Error("profile database initialization failed", "error", err)
		os.Exit(1)
	}
	natEndpoint, err := net.ResolveUDPAddr("udp", cfg.NATAddr)
	if err != nil {
		logger.Error("bandwidth endpoint initialization failed", "error", err)
		os.Exit(1)
	}
	serverIP, err := nat.ResolveAdvertisedIPv4(cfg.NATAdvertisedIP, natEndpoint)
	if err != nil {
		logger.Error("server IP initialization failed", "error", err)
		os.Exit(1)
	}
	authServer.SetBandwidthEndpoint(serverIP, uint16(natEndpoint.Port))
	bandwidthMeasurements := bandwidth.NewStore()
	authServer.SetBandwidthMeasurements(bandwidthMeasurements)
	authServer.SetBandwidthExperiment(cfg.BandwidthSendDurationMS, cfg.BandwidthFinalizeReceivePeriodMS)
	logger.Info("configure your client DNS to use this server", "ip", serverIP.String())
	if cfg.LogSensitive {
		logger.Warn("sensitive protocol logging enabled; logs contain credentials, keys, decrypted payloads, and raw frames")
	}
	lobbyServer := server.NewTCP("lobby", cfg.LobbyAddr, logger, dispatcher, recorder, cfg.MaxFrameBytes, cfg.ReadTimeout, cfg.WriteTimeout)
	natServer := nat.NewWithAddresses(
		cfg.NATAddr,
		cfg.NATAlternateAddr,
		cfg.NATAdvertisedIP,
		cfg.NATRelayEnabled,
		logger,
		recorder,
	)
	natServer.SetBandwidthMeasurements(bandwidthMeasurements)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	type runner struct {
		name string
		run  func(context.Context) error
	}
	stats := func() map[string]uint64 {
		return map[string]uint64{"auth_connections": authServer.Connections(), "auth_requests": authServer.Requests(), "lsg_connections": authServer.LSGConnections(), "lsg_frames": authServer.LSGFrames(), "lobby_connections": lobbyServer.Connections(), "lobby_requests": lobbyServer.Requests(), "nat_packets": natServer.Packets()}
	}
	var adminHandler http.Handler
	if cfg.AdminEnabled {
		assets, err := fs.Sub(os.DirFS(cfg.AdminAssetsDir), ".")
		if err != nil {
			logger.Error("open admin assets", "error", err)
			os.Exit(2)
		}
		var protect func(http.Handler) http.Handler
		if cfg.AdminAllowLocal {
			protect = admin.LocalOnly
		} else {
			validator, err := admin.NewAccessValidator(cfg.AdminAccessTeamDomain, cfg.AdminAccessAudience)
			if err != nil {
				logger.Error("configure admin authentication", "error", err)
				os.Exit(2)
			}
			protect = validator.Middleware
		}
		playlistPath := os.Getenv("MW2_PLAYLISTS_FILE")
		if playlistPath == "" {
			playlistPath = "playlists.info"
		}
		adminHandler = protect(admin.NewServer(authServer, stats, playlistPath, assets).Handler())
	}
	runners := []runner{{"auth", authServer.Serve}, {"lobby", lobbyServer.Serve}, {"nat", natServer.Serve}, {"http", func(ctx context.Context) error {
		return health.ServeWithHandler(ctx, cfg.HTTPAddr, stats, adminHandler)
	}}}
	errCh := make(chan error, len(runners))
	var wg sync.WaitGroup
	for _, item := range runners {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("listener starting", "name", item.name)
			if err := item.run(ctx); err != nil {
				errCh <- fmt.Errorf("%s: %w", item.name, err)
				stop()
			}
		}()
	}
	go func() { wg.Wait(); close(errCh) }()
	for err := range errCh {
		logger.Error("server stopped", "error", err)
	}
}
func parseLevel(value string) slog.Level {
	switch value {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
