package jwt

import (
    "fmt"
    "github.com/google/uuid"
    "github.com/lestrrat-go/jwx/jwa"
    "github.com/lestrrat-go/jwx/jwt"
    "time"
)

type JwtMgr struct {
    Provider *JWKSProvider
}

func NewJwtMgr(provider *JWKSProvider) *JwtMgr {
    return &JwtMgr{
        Provider: provider,
    }
}

func (c *JwtMgr) Validate(tokenStr string) (jwt.Token, error) {
    tok, err := c.validate(tokenStr)
    if err != nil {
        return nil, err
    }
    return tok, nil
}

func (c *JwtMgr) validate(tokenStr string) (jwt.Token, error) {
    tok, err := jwt.ParseString(tokenStr, jwt.WithKeySet(c.Provider.KeySet()))
    if err != nil {
        return nil, fmt.Errorf("valid Token Error:%s ", err.Error())
    }
    return tok, nil
}

func (c *JwtMgr) SignToken(audienceKey, subjectKey, issuerKey string, expire time.Time, opts map[string]interface{}) ([]byte, error) {
    now := time.Now()
    t := jwt.New()
    _ = t.Set(jwt.AudienceKey, audienceKey)
    _ = t.Set(jwt.SubjectKey, subjectKey)
    _ = t.Set(jwt.IssuerKey, issuerKey)
    _ = t.Set(jwt.JwtIDKey, uuid.New().String())
    _ = t.Set(jwt.IssuedAtKey, now)
    _ = t.Set(jwt.ExpirationKey, expire)

    if opts != nil {
        for k, v := range opts {
            _ = t.Set(k, v)
        }
    }

    return jwt.Sign(t, jwa.RS256, c.Provider.JWKForSign())
}
