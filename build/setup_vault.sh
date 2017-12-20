#! /bin/sh
set -ex 

#!/bin/dumb-init /bin/sh

rm -f /opt/healthcheck

#copypasta from upstream docker-entrypoint.sh

# VAULT_CONFIG_DIR isn't exposed as a volume but you can compose additional
# config files in there if you use this image as a base, or use
# VAULT_LOCAL_CONFIG below.
VAULT_CONFIG_DIR=/vault/config

VAULT_SECRETS_FILE=${VAULT_SECRETS_FILE:-"/opt/secrets.json"}
VAULT_APP_ID_FILE=${VAULT_APP_ID_FILE:-"/opt/app-id.json"}
VAULT_POLICIES_FILE=${VAULT_POLICIES_FILE:-"/opt/policies.json"}

# You can also set the VAULT_LOCAL_CONFIG environment variable to pass some
# Vault configuration JSON without having to bind any volumes.
if [ -n "$VAULT_LOCAL_CONFIG" ]; then
    echo "$VAULT_LOCAL_CONFIG" > "$VAULT_CONFIG_DIR/local.json"
fi

vault server \
  -config="$VAULT_CONFIG_DIR" \
  -dev-root-token-id="${VAULT_DEV_ROOT_TOKEN_ID:-root}" \
  -dev-listen-address="${VAULT_DEV_LISTEN_ADDRESS:-"0.0.0.0:8200"}" \
  -dev "$@" &

# end copypasta

# wait for vault to start
until $(vault status | grep "Cluster ID" > /dev/null); do 
  >&2 echo "Vault is unavailable - sleepy time"
  sleep 1
done

>&2 echo "Vault ready - carry on"

# set up vault
token=$(cat $HOME/.vault-token)
echo $token
vault auth $token
vault auth-enable aws
vault write auth/aws/config/client secret_key=$AWS_SECRET_KEY access_key=$AWS_ACCESS_KEY

# set the vault policies
vault policy-write jwt jwt_policy.hcl

# install the jwt plugin
vault write sys/plugins/catalog/jwt sha_256=$(cat /vault/plugins/jwt.sha1) command=jwt

vault auth-disable jwt
vault auth-enable -path=jwt -plugin-name=jwt plugin
