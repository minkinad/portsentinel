FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /portsentinel-server ./cmd/portsentinel-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /portsentinel-server /portsentinel-server
COPY configs/portsentinel.yaml /configs/portsentinel.yaml
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/portsentinel-server", "healthcheck"]
ENTRYPOINT ["/portsentinel-server", "--config", "/configs/portsentinel.yaml"]
