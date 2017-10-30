package josejwt

import (
	"sync"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// JwtBackend export type backend for use else where
type JwtBackend struct {
	*framework.Backend
	view logical.Storage

	// Locks for guarding service clients
	clientMutex sync.RWMutex

	roleLocks []*locksutil.LockEntry
	keyLocks  []*locksutil.LockEntry
}

// Factory returns a new backend as logical.Backend.
func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType is a wrapper func that allows the Factory func to specify
// the backend type for the mock backend plugin instance.
func FactoryType(backendType logical.BackendType) func(*logical.BackendConfig) (logical.Backend, error) {
	return func(conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend(conf)
		b.BackendType = backendType
		if err := b.Setup(conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend export the function to create backend and configure
func Backend(conf *logical.BackendConfig) *JwtBackend {
	backend := &JwtBackend{
		view:      conf.StorageView,
		roleLocks: locksutil.CreateLocks(),
		keyLocks:  locksutil.CreateLocks(),
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		Paths: framework.PathAppend(
			pathToken(backend),
			pathKeys(backend),
		),
	}

	return backend
}
