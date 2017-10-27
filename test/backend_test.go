package josejwt_test

import (
	"testing"

	"github.com/hashicorp/vault/logical"
	jwt "github.com/wenisman/vault_jwt_plugin/plugin"
)

func TestBackend_impl(t *testing.T) {
	var _ logical.Backend = new(jwt.jwtBackend)

	t.Log("backend created")
}

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b := jwt.Backend()

	config := &logical.BackendConfig{}
	err := b.Setup(config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}
