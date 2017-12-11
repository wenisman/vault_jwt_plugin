package josejwt

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
)

// RoleStorageEntry structure that represents the role as it is stored within vault
type RoleStorageEntry struct {
	// `json:"" structs:"" mapstructure:""`
	// The UUID that defines this role
	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	// The unique identifier pointing to the secret for the role
	SecretID string `json:"secret_id" structs:"secret_id" mapstructure:"secret_id"`

	// Policies - the list of policies to apply to the auth
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`

	HMAC string `json:"hmac" structs:"hmac" mapstructure:"hmac"`

	// The TTL for your token
	TokenTTL int `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// The type of token to be created for the role
	TokenType string `json:"token_type" structs:"token_type" mapstructure:"token_type"`

	// The provided name for the role
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// the default claims that will be appended to the role tokens
	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`
}

// get or create the basic lock for the role name
func (backend *JwtBackend) roleLock(roleName string) *locksutil.LockEntry {
	return locksutil.LockForKey(backend.roleLocks, roleName)
}

// roleSave will persist the role in the data store
func (backend *JwtBackend) setRoleEntry(storage logical.Storage, role RoleStorageEntry) error {
	if role.Name == "" {
		return fmt.Errorf("Unable to save, invalid name in role")
	}

	roleName := strings.ToLower(role.Name)

	lock := backend.roleLock(roleName)
	lock.RLock()
	defer lock.RUnlock()

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", roleName), role)
	if err != nil {
		return fmt.Errorf("Error converting entry to JSON: %#v", err)
	}

	if err := storage.Put(entry); err != nil {
		return fmt.Errorf("Error saving role: %#v", err)
	}

	return nil
}

// deleteRoleEntry this will remove the role with specified name
func (backend *JwtBackend) deleteRoleEntry(storage logical.Storage, roleName string) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}
	roleName = strings.ToLower(roleName)

	lock := backend.roleLock(roleName)
	lock.RLock()
	defer lock.RUnlock()

	return storage.Delete(fmt.Sprintf("role/%s", roleName))
}

// getRoleEntry grabs the read lock and fetches the options of an role from the storage
func (backend *JwtBackend) getRoleEntry(storage logical.Storage, roleName string) (*RoleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}
	roleName = strings.ToLower(roleName)

	var result RoleStorageEntry
	if entry, err := storage.Get(fmt.Sprintf("role/%s", roleName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
