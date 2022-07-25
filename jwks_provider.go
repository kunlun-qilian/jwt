package jwt

import (
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "github.com/lestrrat-go/jwx/jwa"
    "github.com/lestrrat-go/jwx/jwk"
    "golang.org/x/crypto/pbkdf2"
)

type JWKSProvider interface {
    JWKForSign() jwk.RSAPrivateKey
    KeySet() jwk.Set
}

type JwtConfig struct {
    PrivateKey Password
    PublicKey  Password

    rsaPrivateKey jwk.RSAPrivateKey
    rsaPublicKey  jwk.RSAPublicKey

    jwks jwk.Set
}

func (j *JwtConfig) JWKForSign() jwk.RSAPrivateKey {
    return j.rsaPrivateKey
}

func (j *JwtConfig) KeySet() jwk.Set {
    return j.jwks
}

func (j *JwtConfig) Init() {
    jwks := jwk.NewSet()

    pk, err := base64.StdEncoding.DecodeString(j.PrivateKey.String())
    if err != nil {
        panic(err)
    }

    privateKey, err := ParseRSAPrivateKeyFromPEM(pk)
    if err != nil {
        panic(err)
    }
    rsaPrivateKey := jwk.NewRSAPrivateKey()

    if err := rsaPrivateKey.FromRaw(privateKey); err != nil {
        panic(err)
    }

    keyID := genKeyID(j.PrivateKey.String())

    headers := map[string]interface{}{
        jwk.KeyIDKey:     keyID,
        jwk.AlgorithmKey: jwa.RS256,
        jwk.KeyUsageKey:  jwk.ForSignature,
    }

    for k := range headers {
        if err := rsaPrivateKey.Set(k, headers[k]); err != nil {
            panic(err)
        }
    }

    j.rsaPrivateKey = rsaPrivateKey

    jwks.Add(rsaPrivateKey)

    j.jwks, _ = jwk.PublicSetOf(jwks)
}

func (j *JwtConfig) Public() {
    jwks := jwk.NewSet()

    publicKey, err := ParseRSAPublicKeyFromPEM([]byte(j.PublicKey.String()))
    if err != nil {
        panic(err)
    }
    rsaPublicKey := jwk.NewRSAPublicKey()

    if err := rsaPublicKey.FromRaw(publicKey); err != nil {
        panic(err)
    }

    keyID := genKeyID(j.PrivateKey.String())

    headers := map[string]interface{}{
        jwk.KeyIDKey:     keyID,
        jwk.AlgorithmKey: jwa.RS256,
        jwk.KeyUsageKey:  jwk.ForSignature,
    }

    for k := range headers {
        if err := rsaPublicKey.Set(k, headers[k]); err != nil {
            panic(err)
        }
    }

    j.rsaPublicKey = rsaPublicKey

    jwks.Add(rsaPublicKey)

    j.jwks, _ = jwk.PublicSetOf(jwks)
}

func genKeyID(pk string) string {
    return base64.RawStdEncoding.EncodeToString(pbkdf2.Key([]byte(pk), []byte("jwt-encrypt"), 7781, 8, sha256.New))
}

var (
    ErrKeyMustBePEMEncoded = errors.New("not pem encoded")
    ErrNotRSAPrivateKey    = errors.New("not rsa private key")
    ErrNotRSAPublicKey     = errors.New("not rsa public key")
)

func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
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

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }
    var parsedKey interface{}
    if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *rsa.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
        return nil, ErrNotRSAPublicKey
    }

    return pkey, nil
}
