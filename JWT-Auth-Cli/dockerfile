## builder for the docker deployed binaries
FROM golang:latest as builder
WORKDIR /go/src/github.com/wenisman/vault-iam-cli
RUN go get -d -v golang.org/x/net/html
COPY . .
RUN go get -v
RUN go test -v ./lib/*
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo .

## build the docker image using the built binaries
FROM alpine:latest
ENV ENVIRONMENT ""

RUN apk --no-cache add ca-certificates

RUN mkdir -p /opt/vault/auth
WORKDIR /opt/vault/auth

COPY --from=builder /go/src/github.com/wenisman/vault-iam-cli .

VOLUME ["/opt/vault/auth"]

EXPOSE 80
