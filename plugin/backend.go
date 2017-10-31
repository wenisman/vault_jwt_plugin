package josejwt

import (
	"sync"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// JwtBackend export type backend for use else where
type JwtBackend struct {
	*framework.Backend
	view logical.Storage

	// The salt value to be used by the information to be accessed only
	// by this backend.
	salt      *salt.Salt
	saltMutex sync.RWMutex

	// Locks for guarding service clients
	clientMutex sync.RWMutex

	roleLocks   []*locksutil.LockEntry
	secretLocks []*locksutil.LockEntry
	keyLocks    []*locksutil.LockEntry
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

// Salt create the Salt for encrypting the keys
func (backend *JwtBackend) Salt() (*salt.Salt, error) {
	backend.saltMutex.RLock()
	if backend.salt != nil {
		defer backend.saltMutex.RUnlock()
		return backend.salt, nil
	}
	backend.saltMutex.RUnlock()
	backend.saltMutex.Lock()
	defer backend.saltMutex.Unlock()
	if backend.salt != nil {
		return backend.salt, nil
	}
	salt, err := salt.NewSalt(backend.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	backend.salt = salt
	return salt, nil
}

// reset the salt
func (backend *JwtBackend) invalidate(key string) {
	switch key {
	case salt.DefaultLocation:
		backend.saltMutex.Lock()
		defer backend.saltMutex.Unlock()
		backend.salt = nil
	}
}

// Backend export the function to create backend and configure
func Backend(conf *logical.BackendConfig) *JwtBackend {
	backend := &JwtBackend{
		view:        conf.StorageView,
		roleLocks:   locksutil.CreateLocks(),
		secretLocks: locksutil.CreateLocks(),
		keyLocks:    locksutil.CreateLocks(),
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		Invalidate:  backend.invalidate,
		Paths: framework.PathAppend(
			pathToken(backend),
			pathKeys(backend),
			pathRole(backend),
		),
	}

	return backend
}
