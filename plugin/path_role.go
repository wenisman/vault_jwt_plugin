package josejwt

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// structure that represents the role as it is stored within vault
type roleStorageEntry struct {
	// `json:"" structs:"" mapstructure:""`
	// The UUID that defines this role
	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	// The unique identifier pointing to the secret for the role
	SecretID string `json:"secret_id" structs:"secret_id" mapstructure:"secret_id"`

	// The type of token to be created for the role
	TokenType string `json:"token_type" structs:"token_type" mapstructure:"token_type"`

	// The provided name for the role
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// check if the role is allowed to provide their own claims when requesting a token
	AllowCustomClaims bool `json:"allow_custom_claims" structs:"allow_custom_claims" mapstructure:"allow_custom_claims"`

	// check if the role is allowed to provide their own payloads when requesting a token
	AllowCustomPayload bool `json:"allow_custom_payload" structs:"allow_custom_payload" mapstructure:"allow_custom_payload"`

	// the default claims that will be appended to the role tokens
	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`
}

// basic schema for the creation of the role, this will map the fields coming in from the
// vault request field map
var createRoleSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the role to be created",
	},
	"token_type": {
		Type:        framework.TypeString,
		Description: "The type of token to be associated to the role [jws|jwt]",
	},
	"claims": {
		Type:        framework.TypeMap,
		Description: "The structure of the claims to be added to the token",
	},
	"allow_custom_claims": {
		Type:        framework.TypeBool,
		Description: "Define if a custom ste of claims can be provided during the creation of the token",
		Default:     false,
	},
	"allow_custom_payload": {
		Type:        framework.TypeBool,
		Description: "Define if a custom payload can be provided during the creation of the token",
		Default:     false,
	},
}

// create the role within plugin, this will provide the access for applications
// to be able to create tokens down the line
func (backend *jwtBackend) createRole(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := backend.roleEntry(req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	if role != nil {
		return logical.ErrorResponse(fmt.Sprintf("role with provided name '%s' already exists", roleName)), nil
	}

	var storageEntry roleStorageEntry
	if err := mapstructure.Decode(data.Raw, &storageEntry); err != nil {
		return logical.ErrorResponse("Error decoding role"), err
	}

	// set the role ID
	roleID, _ := uuid.NewUUID()
	storageEntry.RoleID = roleID.String()

	if err := backend.roleSave(req.Storage, storageEntry); err != nil {
		return logical.ErrorResponse("Error saving role"), err
	}

	roleDetails := map[string]interface{}{
		"role_id": storageEntry.RoleID,
	}
	return &logical.Response{Data: roleDetails}, nil
}

func (backend *jwtBackend) roleSave(storage logical.Storage, role roleStorageEntry) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", role.Name), role)
	if err != nil {
		return fmt.Errorf("Error saving role storage entry: %#v", err)
	}

	if err := storage.Put(entry); err != nil {
		return fmt.Errorf("Error saving role: %#v", err)
	}

	return nil
}

// roleEntry grabs the read lock and fetches the options of an role from the storage
func (backend *jwtBackend) roleEntry(storage logical.Storage, roleName string) (*roleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role_name")
	}
	lock := backend.roleLock(roleName)

	lock.RLock()
	defer lock.RUnlock()

	entry, err := storage.Get(fmt.Sprintf("role/%s", roleName))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleStorageEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// get or create the basic lock for the role name
func (backend *jwtBackend) roleLock(roleName string) *locksutil.LockEntry {
	return locksutil.LockForKey(backend.roleLocks, roleName)
}

// set up the paths for the roles within vault
func pathRole(backend *jwtBackend) []*framework.Path {
	fieldSchema := map[string]*framework.FieldSchema{}
	for k, v := range createRoleSchema {
		fieldSchema[k] = v
	}

	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("role/create/%s", framework.GenericNameRegex("name")),
			Fields:  fieldSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.createRole,
			},
		},
	}

	return paths
}
