package josejwt

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	"github.com/google/uuid"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// structure that represents the role as it is stored within vault
type RoleStorageEntry struct {
	// `json:"" structs:"" mapstructure:""`
	// The UUID that defines this role
	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	// The unique identifier pointing to the secret for the role
	SecretID string `json:"secret_id" structs:"secret_id" mapstructure:"secret_id"`

	// The type of token to be created for the role
	TokenType string `json:"token_type" structs:"token_type" mapstructure:"token_type"`

	// The provided name for the role
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// The secret key used to decode the secret for validation
	HmacKey string `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`

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

// read the current role from the inputs and return it if it exists
func (backend *JwtBackend) readRole(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := backend.getRoleEntry(req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	roleDetails := structs.New(role).Map()
	delete(roleDetails, "role_id")
	delete(roleDetails, "hmac_key")

	return &logical.Response{Data: roleDetails}, nil
}

// create the role within plugin, this will provide the access for applications
// to be able to create tokens down the line
func (backend *JwtBackend) createRole(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := backend.getRoleEntry(req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	if role != nil {
		return logical.ErrorResponse(fmt.Sprintf("role with provided name '%s' already exists", roleName)), nil
	}

	var storageEntry RoleStorageEntry
	if err := mapstructure.Decode(data.Raw, &storageEntry); err != nil {
		return logical.ErrorResponse("Error decoding role"), err
	}

	// set the role ID
	roleID, _ := uuid.NewUUID()
	storageEntry.RoleID = roleID.String()

	if err := backend.setRoleEntry(req.Storage, storageEntry); err != nil {
		return logical.ErrorResponse("Error saving role"), err
	}

	roleDetails := map[string]interface{}{
		"role_id": storageEntry.RoleID,
	}
	return &logical.Response{Data: roleDetails}, nil
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

// roleEntry grabs the read lock and fetches the options of an role from the storage
func (backend *JwtBackend) getRoleEntry(storage logical.Storage, roleName string) (*RoleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}
	roleName = strings.ToLower(roleName)

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

	var result RoleStorageEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// get or create the basic lock for the role name
func (backend *JwtBackend) roleLock(roleName string) *locksutil.LockEntry {
	return locksutil.LockForKey(backend.roleLocks, roleName)
}

// set up the paths for the roles within vault
func pathRole(backend *JwtBackend) []*framework.Path {
	fieldSchema := map[string]*framework.FieldSchema{}
	for k, v := range createRoleSchema {
		fieldSchema[k] = v
	}

	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
			Fields:  fieldSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.createRole,
				logical.ReadOperation:   backend.readRole,
			},
		},
	}

	return paths
}
