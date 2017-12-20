package josejwt

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
)

type secretStorageEntry struct {
	ID           string    `json:"id" structs:"id" mapstructure:"id"`
	Key          string    `json:"Key" structs:"Key" mapstructure:"Key"`
	RoleID       string    `json:"role_id" structs:"role_id" mapstructure:"role_id"`
	Password     string    `json:"password" structs:"password" mapstructure:"password"`
	CreationTime time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`
	Expiration   time.Time `json:"expiration" structs:"expiration" mapstructure:"expiration"`
}

// get or create the basic lock for the secrets
func (backend *JwtBackend) secretLock(secretID string) *locksutil.LockEntry {
	return locksutil.LockForKey(backend.secretLocks, secretID)
}

func (backend *JwtBackend) createSecret(storage logical.Storage, roleID string, TTL int) (*secretStorageEntry, error) {
	// create an UUID for the secret
	secretID, _ := uuid.NewUUID()

	expiration := time.Now().Add(time.Duration(TTL) * time.Second).UTC()
	secretEntry, err := backend.getSecretEntry(storage, roleID, secretID.String())
	if err != nil {
		return nil, fmt.Errorf("Unable to create a new Secret")
	}

	if secretEntry != nil {
		// the secret already exists
		secretEntry.Expiration = expiration
	} else {
		now := time.Now().UTC()
		secretKey, _ := uuid.NewUUID()
		salt, _ := backend.Salt()
		key := salt.GetHMAC(secretKey.String())
		secretEntry = &secretStorageEntry{
			ID:           secretID.String(),
			Key:          key,
			RoleID:       roleID,
			CreationTime: now,
			Expiration:   time.Now().Add(time.Duration(TTL) * time.Second).UTC(),
		}
	}
	// create a new secret, just use a HMAC of a UUID for now

	if err := backend.setSecretEntry(storage, secretEntry); err != nil {
		return nil, err
	}

	return secretEntry, nil
}

// readSecret will either return the currently stored secret or create a new one
// if the secret doesnt exist or the secret has expired
func (backend *JwtBackend) readSecret(storage logical.Storage, roleID string, secretID string) (*secretStorageEntry, error) {
	if roleID == "" {
		return nil, fmt.Errorf("Secrets Role ID is not specified")
	}

	if secretID == "" {
		return nil, fmt.Errorf("Secrets ID is not specified")
	}
	secretEntry, err := backend.getSecretEntry(storage, roleID, secretID)

	if err != nil {
		return nil, err
	}

	if time.Now().UTC().After(secretEntry.Expiration) == true {
		// the secret has expired, delete it and return nil
		backend.deleteSecretEntry(storage, roleID, secretID)
		secretEntry = nil
	}

	// secret is still valid, return it
	return secretEntry, nil
}

// rotateSecret will reset the role ID secret and expiration time
func (backend *JwtBackend) rotateSecret(storage logical.Storage, roleID string, secretID string, TTL int) (*secretStorageEntry, error) {
	if roleID == "" {
		return nil, fmt.Errorf("Secrets Role ID is not specified")
	}

	if secretID == "" {
		return nil, fmt.Errorf("Secrets ID is not specified")
	}

	secretKey, _ := uuid.NewUUID()
	salt, _ := backend.Salt()
	key := salt.GetHMAC(secretKey.String())

	secretEntry, err := backend.getSecretEntry(storage, roleID, secretID)
	if err != nil {
		return nil, err
	}

	secretEntry.Key = key
	secretEntry.CreationTime = time.Now().UTC()
	secretEntry.Expiration = time.Now().Add(time.Duration(TTL) * time.Second).UTC()

	if err := backend.setSecretEntry(storage, secretEntry); err != nil {
		return nil, err
	}

	return secretEntry, nil
}

// getSecretEntry will return the secret entry at the specified location
func (backend *JwtBackend) getSecretEntry(storage logical.Storage, roleID string, secretID string) (*secretStorageEntry, error) {
	if roleID == "" {
		return nil, fmt.Errorf("Secrets Role ID is not specified")
	}

	if secretID == "" {
		return nil, fmt.Errorf("Secrets ID is not specified")
	}

	var result secretStorageEntry
	if entry, err := storage.Get(fmt.Sprintf("secrets/%s/%s", roleID, secretID)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// setSecretEntry will save the secret to the storage
func (backend *JwtBackend) setSecretEntry(storage logical.Storage, entry *secretStorageEntry) error {
	if entry.RoleID == "" {
		return fmt.Errorf("Secrets Role ID is not specified")
	}

	if entry.ID == "" {
		return fmt.Errorf("Secrets ID is not specified")
	}

	lock := backend.secretLock(entry.ID)
	lock.RLock()
	defer lock.RUnlock()

	path := fmt.Sprintf("secrets/%s/%s", entry.RoleID, entry.ID)
	json, err := logical.StorageEntryJSON(path, entry)
	if err != nil {
		return fmt.Errorf("Error converting entry to JSON: %#v", err)
	}

	if err := storage.Put(json); err != nil {
		return fmt.Errorf("Error saving secret: %#v", err)
	}
	return nil
}

// deleteSecretEntry will remove the secret from the storage
func (backend *JwtBackend) deleteSecretEntry(storage logical.Storage, roleID string, secretID string) error {
	if roleID != "" {
		return fmt.Errorf("role ID is not set")
	}

	if secretID != "" {
		return fmt.Errorf("secret ID is not set")
	}

	lock := backend.secretLock(secretID)
	lock.RLock()
	defer lock.RUnlock()

	return storage.Delete(fmt.Sprintf("secrets/%s/%s", roleID, secretID))
}
