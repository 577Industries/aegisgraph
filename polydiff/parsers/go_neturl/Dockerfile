# Pinned for reproducibility against devcontainer/ Go 1.22.5 line.
# Two-stage: build static binary, run from distroless nonroot.

FROM golang:1.22.5-bookworm AS build
WORKDIR /opt/parser
COPY go.mod /opt/parser/go.mod
COPY wrapper.go /opt/parser/wrapper.go
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o wrapper ./wrapper.go

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /opt/parser
COPY --from=build /opt/parser/wrapper /opt/parser/wrapper
USER nonroot:nonroot
ENTRYPOINT ["/opt/parser/wrapper"]
