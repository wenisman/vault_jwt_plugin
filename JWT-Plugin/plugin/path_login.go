package josejwt

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// schema for people to login locally
var loginSchema = map[string]*framework.FieldSchema{
	"role-name": {
		Type:        framework.TypeString,
		Description: "The name of the role to login",
		Default:     "",
	},
	"password": {
		Type:        framework.TypeString,
		Description: "The type of token to be associated to the role [jws|jwt]",
		Default:     "",
	},
}

// Login for the role using a pre-assigned password.
func (backend *JwtBackend) authLoginLocal(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("role-name").(string)
	password := data.Get("password").(string)

	// read role and validate the password.
	roleEntry, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error Retrieving role '%s'", roleName)), nil
	}

	secretEntry, err := backend.getSecretEntry(ctx, req.Storage, roleEntry.RoleID, roleEntry.SecretID)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error Retrieving secrets for role '%s'", roleName)), nil
	}

	salt, _ := backend.Salt()
	passwordHmac := salt.GetHMAC(password)
	if passwordHmac != secretEntry.Password {
		return logical.ErrorResponse("Access Denied"), nil
	}

	ttl, _ := time.ParseDuration("1h")

	return &logical.Response{
		Auth: &logical.Auth{
			Metadata: map[string]string{
				"auth_type": "local",
			},
			InternalData: map[string]interface{}{
				"role_name": roleName,
			},
			Policies: roleEntry.Policies,
			LeaseOptions: logical.LeaseOptions{
				TTL:       ttl,
				Renewable: true,
			},
			DisplayName: roleName,
		},
	}, nil
}

// set up the paths for the roles within vault
func pathLogin(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: "login/local",
			Fields:  loginSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.authLoginLocal,
			},
		},
	}

	return paths
}
