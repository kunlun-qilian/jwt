package jwt

import (
    "fmt"
    "github.com/lestrrat-go/jwx/jwk"
    "github.com/lestrrat-go/jwx/jwt"
)

func NewKeySet(set jwk.Set) *KeySet {
    return &KeySet{
        Set: set,
    }
}

type KeySet struct {
    jwk.Set
}

func (c *KeySet) Validate(tokenStr string) (jwt.Token, error) {
    tok, err := c.validate(tokenStr)
    if err != nil {
        return nil, err
    }
    return tok, nil
}

func (c *KeySet) validate(tokenStr string) (jwt.Token, error) {
    tok, err := jwt.ParseString(tokenStr, jwt.WithKeySet(c))
    if err != nil {
        return nil, fmt.Errorf("valid Token Error:%s ", err.Error())
    }
    return tok, nil
}
