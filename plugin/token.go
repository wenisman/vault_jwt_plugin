package josejwt

import (
	"fmt"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/hashicorp/vault/logical"
)

// TokenCreateEntry is the exposed structure for creating a token
type TokenCreateEntry struct {
	TTL int `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	ClaimName string `json:"claim_name" structs:"claim_name" mapstructure:"claim_name"`

	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`

	RoleName string `json:"role_name" structs:"role_name" mapstructure:"role_name"`

	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	KeyName string `json:"key_name" structs:"key_name" mapstructure:"key_name"`

	TokenType string `json:"token_type" structs:"token_type" mapstructure:"token_type"`
}

// TokenClaims - the structure to hold the claims definitions
type TokenClaims struct {
	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`
}

// Save a set of claims by name so that they can be addressed later
func setTokenClaims(backend *JwtBackend, storage logical.Storage, name string, claims TokenClaims) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("token/claims/%s", name), claims)
	if err != nil {
		return err
	}

	return storage.Put(entry)
}

func getTokenClaims(backend *JwtBackend, storage logical.Storage, name string) (*TokenClaims, error) {
	entry, err := storage.Get(fmt.Sprintf("token/claims/%s", name))
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	if err := entry.DecodeJSON(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func createJwtToken(backend *JwtBackend, storage logical.Storage, createEntry TokenCreateEntry, roleEntry *RoleStorageEntry) (map[string]interface{}, error) {
	claims := jws.Claims{}
	var tokenClaims map[string]string

	if createEntry.ClaimName != "" {
		savedClaims, err := getTokenClaims(backend, storage, createEntry.ClaimName)
		if err != nil {
			return nil, err
		}

		tokenClaims = savedClaims.Claims
	} else {
		tokenClaims = roleEntry.Claims
	}

	for k, v := range tokenClaims {
		claims.Set(k, v)
	}

	utc := time.Now().Add(time.Duration(createEntry.TTL) * time.Second).UTC()
	claims.SetExpiration(utc)

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	token.Claims().Set("role-name", roleEntry.Name)

	// read the secret for this role
	secret, err := backend.readSecret(storage, roleEntry.RoleID, roleEntry.SecretID)
	if err != nil {
		return nil, err
	} else if secret == nil {
		secret, err = backend.rotateSecret(storage, roleEntry.RoleID, roleEntry.SecretID)
		if err != nil {
			return nil, err
		}
	}

	serializedToken, _ := token.Serialize([]byte(secret.Key))
	tokenOutput := map[string]interface{}{
		"ClientToken": string(serializedToken[:]),
	}

	return tokenOutput, nil
}

func (backend *JwtBackend) createTokenEntry(storage logical.Storage, createEntry TokenCreateEntry, roleEntry *RoleStorageEntry) (map[string]interface{}, error) {
	createEntry.TokenType = strings.ToLower(createEntry.TokenType)

	switch createEntry.TokenType {
	case "jws":
		return nil, nil
	case "jwt":
		return createJwtToken(backend, storage, createEntry, roleEntry)
	default:
		// throw an error
		return nil, fmt.Errorf("unsupported token type %s", createEntry.TokenType)
	}
}
