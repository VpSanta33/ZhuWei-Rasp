# ZhuWei-RASP management server image. Build from the server/ directory:
#   docker build -t zhuwei-rasp-server:0.1.0 server/
# Run (data, database and signing key live in the /data volume; back it up):
#   docker run -d --name rasp -p 8480:8480 -v rasp-data:/data \
#     -e RASP_ADMIN_PASSWORD='<at least 12 characters>' -e RASP_AGENT_URL=https://rasp.example.com \
#     zhuwei-rasp-server:0.1.0
# For production pin the base images by digest.

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rasp-server ./cmd/rasp-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rasp-server /rasp-server
# a named volume inherits this ownership on first use, so the non-root server can write to it
COPY --from=build --chown=65532:65532 /out/data /data
ENV RASP_DB=/data/rasp.db RASP_LISTEN=:8480 RASP_OPS_LISTEN=:9480
EXPOSE 8480 9480
VOLUME ["/data"]
USER nonroot
ENTRYPOINT ["/rasp-server"]
