#!/bin/bash

MW2_LOG_LEVEL=debug MW2_LOG_SENSITIVE=true MW2_CAPTURE_ENABLED=true MW2_MATCHMAKING_SUPPRESS_SELF_ONLY=true go run ./cmd/mw2-server/main.go 2>&1 | tee server_log.log