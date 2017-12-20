storage "consul" {
  address = "consul:8500"
  path = "vault"
  token = "consul-vault-token"
  scheme = "http"
  service = "vault"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

plugin_directory = "/vault/plugins"

cluster_addr = "0.0.0.0:8201"