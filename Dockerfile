FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

# Static binaries need no shell, package manager or writable runtime filesystem.
FROM scratch AS server
WORKDIR /app
COPY --from=build /out/server /app/server
COPY rules /app/rules
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/server"]

FROM scratch AS client
WORKDIR /app
COPY --from=build /out/client /app/client
COPY samples /data
USER 65532:65532
ENTRYPOINT ["/app/client"]
CMD ["-server", "http://server:8080", "-input", "/data/banners.json"]
