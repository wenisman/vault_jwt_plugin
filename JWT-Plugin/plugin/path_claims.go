package josejwt

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

var createClaimSchema = map[string]*framework.FieldSchema{
	"claims": {
		Type:        framework.TypeMap,
		Description: "The claims to be put onto the token",
	},
	"name": {
		Type:        framework.TypeString,
		Description: "The human readable name of the claims",
	},
}

// create or update the token claims
func (backend *JwtBackend) createUpdateTokenClaims(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var claims TokenClaims
	if err := mapstructure.Decode(data.Raw, &claims); err != nil {
		return logical.ErrorResponse("Error decoding claims"), err
	}

	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("Claim name not provided"), nil
	}

	if err := setTokenClaims(backend, req.Storage, name, claims); err != nil {
		return logical.ErrorResponse("Unable to save token claims"), err
	}

	output := map[string]interface{}{
		"saved": true,
	}

	return &logical.Response{Data: output}, nil
}

// delete the claim by name, useful for the tidy operations later
func (backend *JwtBackend) removeTokenClaims(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("Claim name is required"), nil
	}

	if err := removeTokenClaims(backend, req.Storage, name); err != nil {
		return logical.ErrorResponse("Unable to remove claim"), err
	}

	output := map[string]interface{}{
		"removed": true,
	}

	return &logical.Response{Data: output}, nil
}

func pathClaims(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("claims/%s", framework.GenericNameRegex("name")),
			Fields:  createClaimSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.createUpdateTokenClaims,
				logical.DeleteOperation: backend.removeTokenClaims,
			},
		},
	}

	return paths
}
