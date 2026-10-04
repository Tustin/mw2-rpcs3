FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY playlists.info THIRD_PARTY_NOTICES.md ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mw2-server ./cmd/mw2-server

FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
COPY files/game_assets/mp/playerdata.def /src/files/game_assets/mp/playerdata.def
RUN npm run build

FROM scratch
COPY --from=build /out/mw2-server /mw2-server
COPY --from=build /src/playlists.info /data/playlists.info
COPY --from=build /src/THIRD_PARTY_NOTICES.md /THIRD_PARTY_NOTICES.md
COPY --from=web-build /src/web/dist /web/dist
COPY ezpatch/test/ez_common_mp.ff /defaults/ez_common_mp.ff
ENV MW2_PLAYLISTS_FILE=/data/playlists.info
ENV MW2_ADMIN_ASSETS_DIR=/web/dist
ENV MW2_EZPATCH_DIR=/data/ezpatch
ENV MW2_EZPATCH_SEED_FILE=/defaults/ez_common_mp.ff
ENV MW2_BANDWIDTH_SEND_DURATION_MS=50
ENV MW2_MATCHMAKING_PREFER_EARLIER_HOSTS=true
EXPOSE 3074/tcp 3074/udp 3075/tcp 3075/udp 8080/tcp
ENTRYPOINT ["/mw2-server"]
