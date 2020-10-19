package auth

import (
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

type Payload struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

func (a *Auth) SignAuthToken(userID string) (string, error) {
	expiredAt := time.Now().Add(a.expiry)
	claims := Payload{
		userID,
		jwt.StandardClaims{
			ExpiresAt: expiredAt.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(a.secret))
}

func (a *Auth) ValidateAuthToken(tok string) (*Payload, error) {
	token, err := jwt.ParseWithClaims(
		tok,
		&Payload{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(a.secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	p, ok := token.Claims.(*Payload)
	if ok && token.Valid {
		return p, nil
	}
	return nil, err
}
