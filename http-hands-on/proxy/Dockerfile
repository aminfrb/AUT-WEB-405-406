# syntax=docker/dockerfile:1

# --- Stage 1: compile a static Go binary ------------------------------------
FROM golang:1.24-alpine AS build
WORKDIR /src
# Standard library only: no dependencies to download, just copy the sources.
COPY . .
# CGO off -> fully static binary that runs in an image without a libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/jwt-proxy .

# --- Stage 2: tiny runtime image ---------------------------------------------
# distroless/static has no shell and no package manager: less to attack.
# The :nonroot tag runs the process as an unprivileged user (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/jwt-proxy /jwt-proxy
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/jwt-proxy"]
