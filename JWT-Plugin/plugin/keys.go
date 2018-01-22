package josejwt

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/logical"
)

// KeyStorageEntry strutcure defines the type of object that is stored
type KeyStorageEntry struct {
	// the name of the private key
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// the type of encryption to use
	Encryption string `json:"enc" structs:"enc" mapstructure:"enc"`

	// the algorithm that the encyrption uses
	Algorithm string `json:"alg" structs:"alg" mapstructure:"alg"`

	// private key can be generated or provided based on alg type
	PrivateKey string `json:"private_key" structs:"private_key" mapstructure:"private_key"`

	// Public key that can be sent to third parties
	PublicKey string `json:"public_key" structs:"public_key" mpastructure:"public_key"`

	// encrypted private key, created based on encyption type
	EncPrivateKey string `json:"enc_private_key" structs:"enc_private_key" mapstructure:"enc_private_key"`
}

func (backend *JwtBackend) getKeyEntry(ctx context.Context, storage logical.Storage, keyName string) (*KeyStorageEntry, error) {
	if keyName == "" {
		return nil, fmt.Errorf("missing key name")
	}
	keyName = strings.ToLower(keyName)

	lock := backend.keyLock(keyName)
	lock.RLock()
	defer lock.RUnlock()

	var result KeyStorageEntry
	if entry, err := storage.Get(ctx, fmt.Sprintf("keys/%s", keyName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Save the key entry to the local storage
func (backend *JwtBackend) setKeyEntry(ctx context.Context, storage logical.Storage, key KeyStorageEntry) error {
	if key.Name == "" {
		return fmt.Errorf("Unable to save key, invalid name")
	}

	keyName := strings.ToLower(key.Name)

	// TODO : put in all the validation for the key

	// TODO : create the key if not set

	lock := backend.keyLock(keyName)
	lock.RLock()
	defer lock.RUnlock()

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("keys/%s", keyName), key)
	if err != nil {
		return fmt.Errorf("Error converting key to JSON: %#v", err)
	}

	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("Error saving key: %#v", err)
	}

	return nil
}
