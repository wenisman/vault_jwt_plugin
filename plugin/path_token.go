package josejwt

import (
	"fmt"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// basic schema for the validation of the token,
// this will map the fields coming in from the vault request field map
var validateTokenSchema = map[string]*framework.FieldSchema{
	"role_name": {
		Type:        framework.TypeString,
		Description: "The role associated with this token",
	},
	"token": {
		Type:        framework.TypeString,
		Description: "The Token to validate",
	},
}

// basic schema for the creation of the token,
// this will map the fields coming in from the vault request field map
var createTokenSchema = map[string]*framework.FieldSchema{
	"claim_name": {
		Type:        framework.TypeString,
		Description: "The name of the ste of claims to use",
	},
	"claims": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The custom claims that are applied to the token",
	},
	"payload": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The custom payload applied to the token",
	},
	"role_name": {
		Type:        framework.TypeString,
		Description: "The name of the role to use in the token",
	},
	"role_id": {
		Type:        framework.TypeString,
		Description: "The unique identifier for the role to use in the token",
	},
	"token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The duration in seconds after which the token will expire",
		Default:     600, // default of 10 minutes
	},
}

// Provides basic token validation for a provided jwt token
func (backend *JwtBackend) validateToken(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	byteToken := []byte(data.Get("token").(string))
	token, err := jws.ParseJWT(byteToken)

	if err != nil {
		return logical.ErrorResponse("unable to parse token"), err
	}

	roleName := data.Get("role_name").(string)
	if roleName == "" {
		roleName = token.Claims().Get("role-name").(string)
	}

	role, err := backend.getRoleEntry(req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("unable to retrieve role details"), err
	}

	secretID := role.SecretID
	tokenID := token.Claims().Get("id").(string)
	if tokenID != "" {
		secretID = tokenID
	}

	secret, err := backend.readSecret(req.Storage, role.RoleID, secretID)
	if err != nil {
		return logical.ErrorResponse("unable to retrieve role secrets"), err
	} else if secret == nil {
		validation := map[string]interface{}{
			"is_valid": false,
		}

		return &logical.Response{Data: validation}, nil
	}

	err = token.Validate([]byte(secret.Key), crypto.SigningMethodHS256)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Invalid Token %#v \n role:%s", err, roleName)), err
	}

	validation := map[string]interface{}{
		"is_valid": true,
	}
	return &logical.Response{Data: validation}, nil
}

// refresh the provided token so that it can live on...
func (backend *JwtBackend) refreshToken(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	byteToken := []byte(data.Get("token").(string))
	token, err := jws.ParseJWT(byteToken)

	if err != nil {
		return logical.ErrorResponse("unable to parse token"), err
	}

	roleName := data.Get("role_name").(string)
	if roleName == "" {
		roleName = token.Claims().Get("role-name").(string)
	}

	role, err := backend.getRoleEntry(req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("unable to retrieve role details"), err
	}
	secretID := role.SecretID
	tokenID := token.Claims().Get("id").(string)
	if tokenID != "" {
		secretID = tokenID
	}

	secret, err := backend.readSecret(req.Storage, role.RoleID, secretID)
	if secret == nil {
		// secret has probably expired so we will make a new one
		secret, err = backend.createSecret(req.Storage, role.RoleID, role.TokenTTL)
	}
	if err != nil {
		return logical.ErrorResponse("Unable to regnerate the secret"), err
	}

	err = token.Validate([]byte(secret.Key), crypto.SigningMethodHS256)
	if err != nil {
		return logical.ErrorResponse("Invalid Token"), err
	}

	expiry := time.Now().Add(time.Duration(role.TokenTTL) * time.Second).UTC()
	token.Claims().SetExpiration(expiry)

	// make sure we update the expiry on the secret
	secret.Expiration = expiry
	backend.setSecretEntry(req.Storage, secret)

	tokenData, _ := token.Serialize([]byte(secret.Key))
	tokenOutput := map[string]interface{}{
		"ClientToken": string(tokenData[:]),
	}

	return &logical.Response{Data: tokenOutput}, nil
}

// split the display name, taking everything after the first dash '-'
func getRoleName(displayName string) string {
	index := strings.Index(displayName, "-")
	if index != -1 {
		return displayName[index+1:]
	}

	return displayName
}

func contains(array []string, value string) bool {
	for _, v := range array {
		if v == value {
			return true
		}
	}

	return false
}

// create the basic jwt token with an expiry within the claim
func (backend *JwtBackend) createToken(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// use the IAM role from the authentication
	roleName := getRoleName(req.DisplayName)

	// get the role by name
	roleEntry, err := backend.getRoleEntry(req.Storage, roleName)
	if roleEntry == nil || err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Role name '%s' not recognised", roleName)), nil
	}

	claimName := data.Get("claim_name").(string)
	if claimName != "" {
		// test if the role can use this claim
		if len(roleEntry.NamedClaims) == 0 || contains(roleEntry.NamedClaims, claimName) == false {
			return logical.ErrorResponse(fmt.Sprintf("Permission denied on claim '%s'", claimName)), nil
		}
	}

	var tokenEntry TokenCreateEntry
	if err := mapstructure.Decode(data.Raw, &tokenEntry); err != nil {
		return logical.ErrorResponse("Error decoding token"), err
	}

	if roleEntry.TokenTTL == 0 {
		// no TTL so use the default of 10 minutes
		tokenEntry.TTL = 600
	} else {
		tokenEntry.TTL = roleEntry.TokenTTL
	}
	tokenEntry.TokenType = roleEntry.TokenType

	token, err := backend.createTokenEntry(req.Storage, tokenEntry, roleEntry)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error creating token, %#v", err)), err
	}

	return &logical.Response{Data: token}, nil
}

func pathToken(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: "token/issue",
			Fields:  createTokenSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.createToken,
			},
		},
		&framework.Path{
			Pattern: "token/validate",
			Fields:  validateTokenSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.validateToken,
			},
		},
	}

	return paths
}
