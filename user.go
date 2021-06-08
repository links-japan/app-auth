package auth

import "github.com/fox-one/mixin-sdk-go"

type User struct {
	MixinUser   *mixin.User
	AccessToken string `json:"access_token"`
	Lang        string `json:"lang"`
}
