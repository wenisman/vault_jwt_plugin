package josejwt

import (
	"context"
	"fmt"
	"time"

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
		Default:     "jwt",
	},
	"policies": {
		Type:        framework.TypeStringSlice,
		Description: "The list of vault policies to assign to the role",
	},
	"named_claims": {
		Type:        framework.TypeStringSlice,
		Description: "The list of named claims to allow onthis role",
	},
	"claims": {
		Type:        framework.TypeMap,
		Description: "The structure of the claims to be added to the token",
	},
	"allow_custom_claims": {
		Type:        framework.TypeBool,
		Description: "Define if a custom set of claims can be provided during the creation of the token",
		Default:     false,
	},
	"allow_custom_payload": {
		Type:        framework.TypeBool,
		Description: "Define if a custom payload can be provided during the creation of the token",
		Default:     false,
	},
	"password": {
		Type:        framework.TypeString,
		Description: "The type of token to be associated to the role [jws|jwt]",
		Default:     "",
	},
	"secret": {
		Type:        framework.TypeString,
		Description: "The secret used to sign the token",
		Default:     "",
	},
}

// remove the specified role from the storage
func (backend *JwtBackend) removeRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to remove, missing role name"), nil
	}

	// get the role to make sure it exists and to get the role id
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// remove the secrets
	backend.deleteSecretEntry(ctx, req.Storage, role.RoleID, role.SecretID)

	// remove the role
	if err := backend.deleteRoleEntry(ctx, req.Storage, roleName); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Unable to remove role %s", roleName)), err
	}

	return &logical.Response{}, nil
}

// read the current role from the inputs and return it if it exists
func (backend *JwtBackend) readRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
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
func (backend *JwtBackend) createRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Role name not supplied"), nil
	}

	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	var secretEntry *secretStorageEntry
	salt, _ := backend.Salt()

	if role == nil {
		role = new(RoleStorageEntry)
		// creating a new role
		if err := mapstructure.Decode(data.Raw, &role); err != nil {
			return logical.ErrorResponse("creating role - Error decoding role"), err
		}

		// set the role ID
		roleID, _ := uuid.NewUUID()
		role.RoleID = roleID.String()
		role.HMAC = salt.GetHMAC(role.RoleID)

		secretEntry, err = backend.createSecret(ctx, req.Storage, role.RoleID, role.TokenTTL)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Unable to create secret entry %#v", err)), nil
		}

		// create the secret
		secret := data.Get("secret").(string)
		if secret != "" {
			// set the secret key to the specified key after its been encrypted
			secretEntry.Key = salt.GetHMAC(secret)
			// remove the expiration on pre-set secrets
			secretEntry.Expiration = time.Time{}
			role.SecretID = secretEntry.ID
		} else {
			role.SecretID = ""
		}

		backend.setSecretEntry(ctx, req.Storage, secretEntry)

	} else {
		// update the role
		secretEntry, err = backend.getSecretEntry(ctx, req.Storage, role.RoleID, role.SecretID)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Unable to retrieve secret entry %#v", err)), nil
		}

		policies := data.Get("policies").([]string)
		if len(policies) > 0 {
			// set the policies if they are provided
			role.Policies = policies
		}

		namedClaims := data.Get("named_claims").([]string)
		if len(namedClaims) > 0 {
			role.NamedClaims = namedClaims
		}
	}

	// if the user has a password we get the hmac and then save it
	password := data.Get("password").(string)
	if password != "" {
		secretEntry.Password = salt.GetHMAC(password)
		backend.setSecretEntry(ctx, req.Storage, secretEntry)
	}

	if err := backend.setRoleEntry(ctx, req.Storage, *role); err != nil {
		return logical.ErrorResponse("Error saving role"), err
	}

	roleDetails := map[string]interface{}{
		"role_id": role.RoleID,
	}
	return &logical.Response{Data: roleDetails}, nil
}

// set up the paths for the roles within vault
func pathRole(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
			Fields:  createRoleSchema,
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
