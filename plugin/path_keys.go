package josejwt

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

var createKeySchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The intended endpoints of the token to validate the claim",
	},
	"alg": {
		Type:        framework.TypeString,
		Description: "The algorithm to use for creating keys",
	},
	"enc": {
		Type:        framework.TypeString,
		Description: "the type of encryption to use when encypting the keys",
	},
	"public_key": {
		Type:        framework.TypeString,
		Description: "The public key for the pem",
	},
	"private_key": {
		Type:        framework.TypeString,
		Description: "The unencrypted private key for the pem",
	},
	"enc_private_key": {
		Type:        framework.TypeString,
		Description: "The encrypted private key",
	},
}

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

// get or create the basic lock for the key name
func (backend *JwtBackend) keyLock(keyName string) *locksutil.LockEntry {
	return locksutil.LockForKey(backend.keyLocks, keyName)
}

func (backend *JwtBackend) createUpdateKey(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyName := data.Get("name").(string)
	key, err := backend.getKeyEntry(req.Storage, keyName)
	if err != nil {
		return logical.ErrorResponse("Error reading key"), err
	}

	if key != nil {
		return logical.ErrorResponse(fmt.Sprintf("key with provided name '%s' already exists", keyName)), nil
	}
	var storageEntry KeyStorageEntry
	if err := mapstructure.Decode(data.Raw, &storageEntry); err != nil {
		return logical.ErrorResponse("Error decoding role"), err
	}
	backend.setKeyEntry(req.Storage, storageEntry)

	return &logical.Response{}, nil
}

func (backend *JwtBackend) readKey(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyName := data.Get("name").(string)

	key, err := backend.getKeyEntry(req.Storage, keyName)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Unable to retrieve key %s", keyName)), nil
	} else if key == nil {
		return logical.ErrorResponse(fmt.Sprintf("Key %s does not exist", keyName)), nil
	}

	keyDetails := structs.New(key).Map()
	delete(keyDetails, "private_key")
	delete(keyDetails, "enc_private_key")

	return &logical.Response{Data: keyDetails}, nil
}

func (backend *JwtBackend) getKeyEntry(storage logical.Storage, keyName string) (*KeyStorageEntry, error) {
	if keyName == "" {
		return nil, fmt.Errorf("missing key name")
	}
	keyName = strings.ToLower(keyName)

	lock := backend.keyLock(keyName)
	lock.RLock()
	defer lock.RUnlock()

	var result KeyStorageEntry
	if entry, err := storage.Get(fmt.Sprintf("keys/%s", keyName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Save the key entry to the local storage
func (backend *JwtBackend) setKeyEntry(storage logical.Storage, key KeyStorageEntry) error {
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

	if err := storage.Put(entry); err != nil {
		return fmt.Errorf("Error saving key: %#v", err)
	}

	return nil
}

// set up the paths for the roles within vault
func pathKeys(backend *JwtBackend) []*framework.Path {
	fieldSchema := map[string]*framework.FieldSchema{}
	for k, v := range createKeySchema {
		fieldSchema[k] = v
	}

	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("keys/%s", framework.GenericNameRegex("name")),
			Fields:  fieldSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.createUpdateKey,
				logical.UpdateOperation: backend.createUpdateKey,
				logical.ReadOperation:   backend.readKey,
			},
		},
	}

	return paths
}
