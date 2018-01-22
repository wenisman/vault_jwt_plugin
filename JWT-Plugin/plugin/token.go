package josejwt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/logical"
)

// TokenCreateEntry is the exposed structure for creating a token
type TokenCreateEntry struct {
	TTL int `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	ID string `json:"id" structs:"id" mapstructure:"id"`

	ClaimName string `json:"claim_name" structs:"claim_name" mapstructure:"claim_name"`

	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`

	RoleName string `json:"role_name" structs:"role_name" mapstructure:"role_name"`

	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	KeyName string `json:"key_name" structs:"key_name" mapstructure:"key_name"`

	TokenType string `json:"token_type" structs:"token_type" mapstructure:"token_type"`
}

func createJwtToken(ctx context.Context, backend *JwtBackend, storage logical.Storage, createEntry TokenCreateEntry, roleEntry *RoleStorageEntry) (map[string]interface{}, error) {
	claims := jws.Claims{}
	var tokenClaims map[string]string

	id, _ := uuid.NewUUID()
	tokenID := id.String()

	if createEntry.ClaimName != "" {
		savedClaims, err := getTokenClaims(ctx, backend, storage, createEntry.ClaimName)
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
	secret, err := backend.readSecret(ctx, storage, roleEntry.RoleID, roleEntry.SecretID)
	if err != nil {
		return nil, err
	} else if secret == nil {
		// theres no secret so lets create a new secret for this token
		secret, err = backend.createSecret(ctx, storage, roleEntry.RoleID, roleEntry.TokenTTL)
		if err != nil {
			return nil, err
		}
		secret.ID = tokenID
		if err := backend.setSecretEntry(ctx, storage, secret); err != nil {
			return nil, fmt.Errorf("Unable to set the secret entry")
		}
		token.Claims().Set("id", tokenID)
	}

	serializedToken, _ := token.Serialize([]byte(secret.Key))
	tokenOutput := map[string]interface{}{
		"ClientToken": string(serializedToken[:]),
	}

	return tokenOutput, nil
}

func (backend *JwtBackend) createTokenEntry(ctx context.Context, storage logical.Storage, createEntry TokenCreateEntry, roleEntry *RoleStorageEntry) (map[string]interface{}, error) {
	createEntry.TokenType = strings.ToLower(createEntry.TokenType)

	switch createEntry.TokenType {
	case "jws":
		return nil, nil
	case "jwt":
		return createJwtToken(ctx, backend, storage, createEntry, roleEntry)
	default:
		// throw an error
		return nil, fmt.Errorf("unsupported token type %s", createEntry.TokenType)
	}
}
