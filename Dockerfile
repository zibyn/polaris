FROM --platform=$BUILDPLATFORM node:24-alpine AS web
RUN npm install -g pnpm@12.4.2
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.27 AS go
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist/client web/dist/client
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags=-s -o /polaris ./cmd/polaris

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /polaris /polaris
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s CMD ["/polaris", "healthcheck"]
ENTRYPOINT ["/polaris"]
