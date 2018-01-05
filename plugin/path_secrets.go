package josejwt

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (backend *JwtBackend) tidySecrets(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := backend.tidySecretEntries(req.Storage)
	if err != nil {
		return logical.ErrorResponse("tidySecrets - Unable to tidy the secrets"), err
	}

	return &logical.Response{}, err
}

// set up the paths for the roles within vault
func pathSecrets(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: "secrets/tidy",
			Fields:  createKeySchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.tidySecrets,
			},
		},
	}

	return paths
}
