package josejwt

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
)

// TokenClaims - the structure to hold the claims definitions
type TokenClaims struct {
	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`
}

// get or create the basic lock for the role name
func (backend *JwtBackend) claimLock(name string) *locksutil.LockEntry {
	return locksutil.LockForKey(backend.claimLocks, name)
}

// Save a set of claims by name so that they can be addressed later
func setTokenClaims(ctx context.Context, backend *JwtBackend, storage logical.Storage, name string, claims TokenClaims) error {
	lock := backend.claimLock(name)
	lock.RLock()
	defer lock.RUnlock()

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("claims/%s", name), claims)
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

// Get the set of claims by the name provided
func getTokenClaims(ctx context.Context, backend *JwtBackend, storage logical.Storage, name string) (*TokenClaims, error) {
	entry, err := storage.Get(ctx, fmt.Sprintf("claims/%s", name))
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	if err := entry.DecodeJSON(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// remove the claims by the specified name
func removeTokenClaims(ctx context.Context, backend *JwtBackend, storage logical.Storage, name string) error {
	lock := backend.claimLock(name)
	lock.RLock()
	defer lock.RUnlock()
	if name == "" {
		return fmt.Errorf("Claim name is required")
	}

	return storage.Delete(ctx, fmt.Sprintf("claims/%s", name))
}
