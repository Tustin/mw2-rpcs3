FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY playlists.info THIRD_PARTY_NOTICES.md ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mw2-server ./cmd/mw2-server

FROM scratch
COPY --from=build /out/mw2-server /mw2-server
COPY --from=build /src/playlists.info /playlists.info
COPY --from=build /src/THIRD_PARTY_NOTICES.md /THIRD_PARTY_NOTICES.md
ENV MW2_PLAYLISTS_FILE=/playlists.info
EXPOSE 3074/tcp 3074/udp 3075/tcp 3075/udp 8080/tcp
ENTRYPOINT ["/mw2-server"]
