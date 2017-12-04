package josejwt

import (
	"fmt"

	"github.com/fatih/structs"
	"github.com/google/uuid"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// basic schema for the creation of the role, this will map the fields coming in from the
// vault request field map
var createRoleSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the role to be created",
	},
	"token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The TTL of the token",
		Default:     600,
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

// remove the specified role from the storage
func (backend *JwtBackend) removeRole(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to remove, missing role name"), nil
	}

	// get the role to make sure it exists and to get the role id
	role, err := backend.getRoleEntry(req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// remove the secrets
	backend.deleteSecretEntry(req.Storage, role.RoleID, role.SecretID)

	// remove the role
	if err := backend.deleteRoleEntry(req.Storage, roleName); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Unable to remove role %s", roleName)), err
	}

	return &logical.Response{}, nil
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
	delete(roleDetails, "secret_id")
	delete(roleDetails, "hmac")

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
		return logical.ErrorResponse(fmt.Sprintf("role with name '%s' already exists", roleName)), nil
	}

	var storageEntry RoleStorageEntry
	if err := mapstructure.Decode(data.Raw, &storageEntry); err != nil {
		return logical.ErrorResponse("Error decoding role"), err
	}

	// set the role ID
	roleID, _ := uuid.NewUUID()
	storageEntry.RoleID = roleID.String()
	salt, _ := backend.Salt()
	storageEntry.HMAC = salt.GetHMAC(storageEntry.RoleID)

	// create the secret
	secretEntry, err := backend.createSecret(req.Storage, storageEntry.RoleID)
	storageEntry.SecretID = secretEntry.ID

	if err := backend.setRoleEntry(req.Storage, storageEntry); err != nil {
		return logical.ErrorResponse("Error saving role"), err
	}

	roleDetails := map[string]interface{}{
		"role_id": storageEntry.RoleID,
	}
	return &logical.Response{Data: roleDetails}, nil
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
				logical.UpdateOperation: backend.createRole,
				logical.ReadOperation:   backend.readRole,
				logical.DeleteOperation: backend.removeRole,
			},
		},
	}

	return paths
}
