module github.com/links-japan/app-auth

go 1.14

require (
	github.com/btcsuite/btcd v0.21.0-beta // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ethereum/go-ethereum v1.9.23 // indirect
	github.com/fox-one/mixin-sdk-go v1.1.2
	github.com/gin-gonic/gin v1.6.3
	github.com/go-playground/validator/v10 v10.4.1 // indirect
	github.com/gobuffalo/envy v1.9.0 // indirect
	github.com/gobuffalo/packd v1.0.0 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/rogpeppe/go-internal v1.6.2 // indirect
	github.com/ugorji/go v1.1.12 // indirect
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897 // indirect
	golang.org/x/net v0.0.0-20201016165138-7b1cca2348c0 // indirect
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	golang.org/x/sync v0.0.0-20201008141435-b3e1573b7520 // indirect
	golang.org/x/sys v0.0.0-20201018121011-98379d014ca7 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gorm.io/driver/mysql v1.0.2
	gorm.io/gorm v1.20.2
)

replace golang.org/x/oauth2 => github.com/links-japan/oauth2 v0.0.0-20201015082125-603282e70902
