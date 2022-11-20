package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"time"
)

var (
	ErrKeyMustBePEMEncoded = errors.New("not pem encoded")
	ErrNotRSAPrivateKey    = errors.New("not rsa private key")
)

func NewJwtMgr(privateKey string) *JwtMgr {
	return &JwtMgr{
		privateKey: privateKey,
	}
}

type JwtMgr struct {
	privateKey    string
	rsaPrivateKey jwk.Key
	rsaPublicKey  jwk.Key
}

func (c *JwtMgr) Init() {
	pk, err := base64.StdEncoding.DecodeString(c.privateKey)
	if err != nil {
		panic(err)
	}

	r, err := c.parseRSAPrivateKeyFromPEM(pk)
	if err != nil {
		panic(err)
	}

	c.rsaPrivateKey, err = jwk.FromRaw(r)
	if err != nil {
		panic(err)
	}

	c.rsaPublicKey, err = jwk.PublicKeyOf(c.rsaPrivateKey)
	if err != nil {
		panic(err)
	}
}

func (c *JwtMgr) parseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

func (g *JwtMgr) SignToken(audienceKey, subjectKey, issuerKey string, expire time.Time) ([]byte, error) {
	now := time.Now()
	t := jwt.New()
	_ = t.Set(jwt.AudienceKey, audienceKey)
	_ = t.Set(jwt.SubjectKey, subjectKey)
	_ = t.Set(jwt.IssuerKey, issuerKey)
	_ = t.Set(jwt.JwtIDKey, uuid.New().String())
	_ = t.Set(jwt.IssuedAtKey, now)
	_ = t.Set(jwt.ExpirationKey, expire)
	return jwt.Sign(t, jwt.WithKey(jwa.RS256, g.rsaPrivateKey))
}

func (c *JwtMgr) ParseToken(token string) (jwt.Token, error) {
	return jwt.ParseString(token, jwt.WithKey(jwa.RS256, c.rsaPublicKey))
}

func (c *JwtMgr) TokenExpired(t jwt.Token) bool {
	return time.Now().Unix() > t.Expiration().Unix()
}
