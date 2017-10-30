package josejwt_test

import (
	"log"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
	jwt "github.com/wenisman/vault_jwt_plugin/plugin"
)

func Test_Backend_Impl(t *testing.T) {
	var _ logical.Backend = new(jwt.JwtBackend)

	t.Log("backend created")
}

// default method for timing the execution of a method
func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

// return the mocked out backend for testing
func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := jwt.Backend(config)

	err := b.Setup(config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}
