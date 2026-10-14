FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/caretakarr ./cmd/caretakarr \
 && mkdir /data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/caretakarr /caretakarr
COPY --from=build --chown=65532:65532 /data /data
COPY LICENSE NOTICE /licenses/
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 80 443 443/udp
ENTRYPOINT ["/caretakarr"]
