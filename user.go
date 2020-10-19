package auth

import "github.com/fox-one/mixin-sdk-go"

type User struct {
	MixinUser   *mixin.User
	AccessToken string
	Lang        string
}
