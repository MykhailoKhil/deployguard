# Build stage: static binary, no CGO.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/deployguard ./cmd/deployguard

# Run stage: no shell, non-root, CA certificates included for GitHub/AI HTTPS.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/deployguard /deployguard
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/deployguard"]
