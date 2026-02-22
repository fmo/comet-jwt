package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Header struct {
	Alg string
	Typ string
}

type JWT struct {
	Header Header
	Claims map[string]string
}

func (jwt *JWT) Sign(claims map[string]string, secret string) string {
	h := Header{"HS256", "JWT"}

	// convert header to json
	headerJSON, _ := json.Marshal(h)

	// convert claims to json
	claimsJSON, _ := json.Marshal(claims)

	// get base 64 of it
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// get base 64 of claims
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	completeString := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)

	// sign the base64 string
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(completeString))

	signature := mac.Sum(nil)

	// encode the signature
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signatureEncoded)
}

func main() {
	j := JWT{}

	jwt := j.Sign(map[string]string{"sub": "mustafa"}, "hello")

	fmt.Println(jwt)
}
