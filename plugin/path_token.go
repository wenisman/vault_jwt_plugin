package josejwt

import (
	"log"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// basic schema for the validation of the token,
// this will map the fields coming in from the vault request field map
var validateTokenSchema = map[string]*framework.FieldSchema{
	"aud": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The intended endpoints of the token to validate the claim",
	},
	"token": {
		Type:        framework.TypeString,
		Description: "The Token to validate",
	},
}

// basic schema for the creation of the token,
// this will map the fields coming in from the vault request field map
var createTokenSchema = map[string]*framework.FieldSchema{
	"aud": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The intended endpoints of the token to validate the claim",
	},
	"ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The duration in seconds after which the token will expire",
		Default:     600, // default of 10 minutes
	},
	"max_ttl": {
		Type:        framework.TypeDurationSecond,
		Default:     3600, // default 1 hour
		Description: "The maximum duration of tokens issued.",
	},
}

// Provides basic token validation for a provided jwt token
func (backend *JwtBackend) validateToken(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	byteToken := []byte(data.Get("token").(string))
	token, _ := jws.ParseJWT(byteToken)

	err := token.Validate([]byte("secret"), crypto.SigningMethodHS256)
	if err != nil {
		return logical.ErrorResponse("Invalid Token"), nil
	}

	claims, ok := token.Claims().Audience()
	if !ok {
		return logical.ErrorResponse("Invalid Claims on token"), nil
	}

	// TODO : validate the claims
	log.Printf("Returned Claims %s", claims)

	validation := map[string]interface{}{
		"is_valid": true,
	}
	return &logical.Response{Data: validation}, nil
}

// create the basic jwt token with an expiry wihtin the claim
func (backend *JwtBackend) createToken(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	aud := data.Get("aud").([]string)

	// TODO : move this logic into an config struct... but im just hackin at the mo
	ttl := data.Get("ttl").(int)
	maxTTL := data.Get("max_ttl").(int)

	if maxTTL < ttl {
		ttl = maxTTL
	}

	if len(aud) == 0 {
		return logical.ErrorResponse("No specified Audience"), nil
	}

	claims := jws.Claims{}
	for _, a := range aud {
		claims.SetAudience(a)
	}

	claims.SetExpiration(time.Now().UTC().Add(time.Duration(ttl) * time.Second))
	token := jws.NewJWT(claims, crypto.SigningMethodHS256)

	serializedToken, _ := token.Serialize([]byte("secret"))
	tokenOutput := map[string]interface{}{"ClientToken": string(serializedToken[:])}

	return &logical.Response{Data: tokenOutput}, nil
}

func pathToken(backend *JwtBackend) []*framework.Path {
	tokenSchema := map[string]*framework.FieldSchema{}
	for k, v := range createTokenSchema {
		tokenSchema[k] = v
	}

	for k, v := range validateTokenSchema {
		tokenSchema[k] = v
	}

	paths := []*framework.Path{
		&framework.Path{
			Pattern: "token/issue",
			Fields:  tokenSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: backend.createToken,
			},
		},
		&framework.Path{
			Pattern: "token/validate",
			Fields:  tokenSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: backend.validateToken,
			},
		},
	}

	return paths
}
