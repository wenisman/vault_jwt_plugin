FROM golang:latest as builder

WORKDIR /go/src/github.com/wenisman/vault_jwt_plugin

RUN go get -d -v golang.org/x/net/html

COPY . .

RUN go get -v
RUN go test -v ./test/*
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o jwt 
RUN shasum -a 256 -p jwt | cut -d ' ' -f 1 > "jwt.sha1"

## build the docker container with vault and the plugin mounted
FROM vault

ENV VAULT_PORT 8200
ENV VAULT_TOKEN ""
ENV VAULT_ADDR ""
ENV VAULT_CLUSTER_ADDR ""
ENV VAULT_API_ADDR ""
ENV AWS_ACCESS_KEY ""
ENV AWS_SECRET_KEY ""

RUN apk --no-cache add ca-certificates
RUN mkdir -p /vault/plugins

# set up the AWS Auth backend
WORKDIR /vault/plugins

RUN /vault/plugins/wait_for_vault.sh

RUN token=$(cat $HOME/.vault-token) && \
    vault auth $token && \
    vault auth-enable aws && \
    vault write auth/aws/config/client secret_key=$AWS_SECRET_KEY access_key=$AWS_ACCESS_KEY


COPY --from=builder /go/src/github.com/wenisman/vault_jwt_plugin/build/* .

RUN ./redeploy.sh jwt && \
    vault policy-write jwt jwt_policy.hcl

# mount point for a vault config
VOLUME [ "/vault/config" ]

EXPOSE ${VAULT_PORT}