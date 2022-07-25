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

    // 是否校验过期
    checkExpired bool
}

func NewJwtMgr(provider *JWKSProvider, checkExpired bool) *JwtMgr {
    return &JwtMgr{
        Provider:     provider,
        checkExpired: checkExpired,
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

func (c *JwtMgr) ValidateTokenByTokenKey(tokenKey, token string) (jwt.Token, error) {

    auth := ParseAuthorization(token)
    t, err := c.Validate(auth.Get(tokenKey))
    if err != nil {
        return nil, err
    }

    if c.checkExpired {
        if time.Now().Unix() > t.Expiration().Unix() {
            return nil, fmt.Errorf("token expired")
        }
    }

    return t, nil
}
