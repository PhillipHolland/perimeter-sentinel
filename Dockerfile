# Build a static perimeterctl. The runtime image has no shell and no keys.
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/perimeterctl ./cmd/perimeterctl

FROM scratch
COPY --from=build /out/perimeterctl /perimeterctl
USER 65532:65532
ENTRYPOINT ["/perimeterctl"]
