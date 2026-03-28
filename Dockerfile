FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/bulwark ./cmd/bulwark

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/bulwark /bulwark
# Bake in a default dev config so the image works out-of-the-box in
# docker compose without any volume mount or configs.content support.
# Override at runtime with: -v ./your.yaml:/etc/bulwark/bulwark.yaml:ro
COPY testdata/docker-bulwark.yaml /etc/bulwark/bulwark.yaml

EXPOSE 8080
ENTRYPOINT ["/bulwark"]
CMD ["serve", "--config", "/etc/bulwark/bulwark.yaml"]
