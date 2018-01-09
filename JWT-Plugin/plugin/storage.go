package josejwt

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
)

// generic method to save the tiem to the storage at the defined path
func (backend *JwtBackend) storageSetItem(storage logical.Storage, path string, item interface{}) error {
	entry, err := logical.StorageEntryJSON(path, item)
	if err != nil {
		return fmt.Errorf("Error converting entry to JSON: %#v", err)
	}

	if err := storage.Put(entry); err != nil {
		return fmt.Errorf("Error saving item: %#v", err)
	}

	return nil
}
