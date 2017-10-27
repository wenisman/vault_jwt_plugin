package josejwt

import (
	"sync"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// jwtBackend export type backend for use else where
type jwtBackend struct {
	*framework.Backend

	// Locks for guarding service clients
	clientMutex sync.RWMutex

	roleLocks []*locksutil.LockEntry
}

// New returns a new backend as an interface. This func
// is only necessary for builtin backend plugins.
func New() (interface{}, error) {
	return Backend(), nil
}

// Factory returns a new backend as logical.Backend.
func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType is a wrapper func that allows the Factory func to specify
// the backend type for the mock backend plugin instance.
func FactoryType(backendType logical.BackendType) func(*logical.BackendConfig) (logical.Backend, error) {
	return func(conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend()
		b.BackendType = backendType
		if err := b.Setup(conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend export the function to create backend and configure
func Backend() *jwtBackend {
	backend := &jwtBackend{}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		Paths: framework.PathAppend(
			pathToken(backend),
		),
	}

	return backend
}