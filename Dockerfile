FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mw2-server ./cmd/mw2-server

FROM scratch
COPY --from=build /out/mw2-server /mw2-server
EXPOSE 3074/tcp 3075/tcp 3076/udp 8080/tcp
ENTRYPOINT ["/mw2-server"]
