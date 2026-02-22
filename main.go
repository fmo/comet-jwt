package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Sub string `json:"sub,omitempty"` // Subject - userID
	Iss string `json:"iss,omitempty"` // Issuer - auth-service
	Aud string `json:"aud,omitempty"` // Aud - audience payments-service
	Exp int64  `json:"exp,omitempty"` // Experition
	Iat int64  `json:"iat,omitempty"` // Issued At
	Nbf int64  `json:"nbf,omitempty"` // Not Before
}

type JWT struct {
	Secret string
}

func (jwt *JWT) Sign(claims Claims) string {
	// convert header to json
	headerJSON, _ := json.Marshal(Header{"HS256", "JWT"})

	// convert claims to json
	claimsJSON, _ := json.Marshal(claims)

	// get base 64 of it
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// get base 64 of claims
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	completeString := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)

	// sign the base64 string
	mac := hmac.New(sha256.New, []byte(jwt.Secret))
	mac.Write([]byte(completeString))

	signature := mac.Sum(nil)

	// encode the signature
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signatureEncoded)
}

func (jwt *JWT) Verify(token string) {
	tokenArr := strings.Split(token, ".")
	if len(tokenArr) != 3 {
		return
	}

	_, err := base64.RawURLEncoding.DecodeString(tokenArr[0])
	if err != nil {
		return
	}

	claims, err := base64.RawURLEncoding.DecodeString(tokenArr[1])
	if err != nil {
		return
	}

	_, err = base64.RawURLEncoding.DecodeString(tokenArr[2])
	if err != nil {
		return
	}

	cls := Claims{}

	json.Unmarshal(claims, &cls)

	fmt.Println(cls)

}

func main() {
	claims := Claims{
		Sub: "user-1222",
		Exp: time.Now().Add(2 * time.Minute).Unix(),
	}

	j := JWT{"secret"}
	jwt := j.Sign(claims)

	fmt.Println(jwt)

	j.Verify(jwt)
}
