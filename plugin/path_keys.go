package josejwt

import (
	"fmt"

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
