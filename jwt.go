package jwt

import (
    "fmt"
    "github.com/lestrrat-go/jwx/jwk"
    "github.com/lestrrat-go/jwx/jwt"
)

type JwtMgr struct {
    jwk.Set
}

func NewJwtMgr(set jwk.Set) *JwtMgr {
    return &JwtMgr{
        Set: set,
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
    tok, err := jwt.ParseString(tokenStr, jwt.WithKeySet(c))
    if err != nil {
        return nil, fmt.Errorf("valid Token Error:%s ", err.Error())
    }
    return tok, nil
}
