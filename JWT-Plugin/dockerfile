FROM golang:latest as builder

WORKDIR /go/src/github.com/wenisman/vault_jwt_plugin

RUN go get -d -v golang.org/x/net/html

COPY . .

RUN go get -v
RUN go test -v ./test/*
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/jwt 
RUN shasum -a 256 -p build/jwt | cut -d ' ' -f 1 > "build/jwt.sha1"

## build the docker container with vault and the plugin mounted
FROM vault:latest

ENV VAULT_PORT 8200
ENV VAULT_TOKEN ""
ENV VAULT_ADDR "http://0.0.0.0:${VAULT_PORT}"
ENV VAULT_CLUSTER_ADDR ""
ENV VAULT_API_ADDR ""
ENV VAULT_LOCAL_CONFIG '{ "plugin_directory": "/vault/plugins" }'
ENV AWS_ACCESS_KEY ""
ENV AWS_SECRET_KEY ""

RUN apk --no-cache add ca-certificates
RUN mkdir -p /vault/plugins

EXPOSE ${VAULT_PORT}

# set up the AWS Auth backend
WORKDIR /vault/plugins
COPY --from=builder /go/src/github.com/wenisman/vault_jwt_plugin/build /vault/plugins

RUN chmod a+x *.sh
RUN ./setup_vault.sh

ENTRYPOINT [ "/vault/plugins/start_vault.sh" ]

# mount point for a vault config
VOLUME [ "/vault/config" ]

CMD ["server", "-dev"]
