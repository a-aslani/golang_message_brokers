package token

import (
	"context"
	"crypto/rand"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/a-aslani/golang_message_brokers/configs"
	"github.com/golang-jwt/jwt"
	"github.com/redis/go-redis/v9"
	"os"
	"strings"
	"time"
)

const (
	TableName = "refresh_token"
)

var (
	verifyKey     *rsa.PublicKey
	signKey       *rsa.PrivateKey
	refreshTokens map[string]string
	preTokenName  = "Bearer"
)

type Claims struct {
	UserID string `json:"user_id"`
	Csrf   string `json:"csrf"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	Csrf string `json:"csrf"`
	jwt.StandardClaims
}

type RefreshToken struct {
	Subject string `json:"subject" bson:"subject"`
	JTI     string `json:"jti" bson:"jti"`
}

type JWTToken struct {
	algorithm             jwt.SigningMethod
	secretKey             string
	refreshTokenValidTime time.Duration
	accessTokenValidTime  time.Duration
	rdb                   *redis.Client
}

type JWT interface {
	GenerateToken(ctx context.Context, userId string, sub string) (accessToken, refreshToken, csrfSecret string, expiresAt int64, err error)
	RenewToken(ctx context.Context, oldAccessTokenString string, oldRefreshTokenString, oldCsrfSecret string) (newAccessToken, newRefreshToken, newCsrfSecret string, expiresAt int64, userId string, err error)
	DeleteRefreshToken(ctx context.Context, sub string, jti string) error
	VerifyToken(token string) (*Claims, error)
}

func initDbClient(cfg *configs.Config) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       0,
	})
	return rdb
}

func NewHS256JWT(ctx context.Context, cfg *configs.Config, refreshTokenValidTime time.Duration, accessTokenValidTime time.Duration) (JWT, error) {

	rdb := initDbClient(cfg)

	jwtToken := &JWTToken{
		algorithm:             jwt.SigningMethodHS256,
		secretKey:             cfg.JWTSecretKey,
		refreshTokenValidTime: refreshTokenValidTime,
		accessTokenValidTime:  accessTokenValidTime,
		rdb:                   rdb,
	}

	err := jwtToken.initCachedRefreshTokens(ctx)
	if err != nil {
		return nil, err
	}

	return jwtToken, nil
}

func NewRS256JWT(ctx context.Context, cfg *configs.Config, fileName string, refreshTokenValidTime time.Duration, accessTokenValidTime time.Duration) (JWT, error) {

	err := initRS256JWT(fileName)
	if err != nil {
		return nil, err
	}

	rdb := initDbClient(cfg)

	jwtToken := &JWTToken{
		algorithm:             jwt.SigningMethodRS256,
		refreshTokenValidTime: refreshTokenValidTime,
		accessTokenValidTime:  accessTokenValidTime,
		rdb:                   rdb,
	}

	err = jwtToken.initCachedRefreshTokens(ctx)
	if err != nil {
		return nil, err
	}

	return jwtToken, nil
}

func initRS256JWT(fileName string) error {
	assetsDir := "assets"
	keysDir := "keys"
	path := fmt.Sprintf("%s/%s", assetsDir, keysDir)

	if _, err := os.Stat(fmt.Sprintf("./%s", assetsDir)); os.IsNotExist(err) {
		_ = os.Mkdir(fmt.Sprintf("./%s", assetsDir), 0755)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = os.Mkdir(path, 0755)
	}

	if _, err := os.Stat(fmt.Sprintf("%s/%s.rsa", path, fileName)); os.IsNotExist(err) {
		err = generateRSAKeys(path, fileName)
		if err != nil {
			return err
		}
	}

	privateKeyPath := fmt.Sprintf("%s/%s.rsa", path, fileName)
	publicKeyPath := fmt.Sprintf("%s/%s.rsa.pub", path, fileName)

	signBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func generateRSAKeys(path string, fileName string) (err error) {
	// generate key
	privateKey, err := rsa.GenerateKey(cRand.Reader, 2048)
	if err != nil {
		return
	}
	publicKey := &privateKey.PublicKey

	// dump private key to file
	var privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privatePem, err := os.Create(path + "/" + fileName + ".rsa")
	if err != nil {
		return
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(path + "/" + fileName + ".rsa.pub")
	if err != nil {
		return
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return
	}

	return
}

func (t *JWTToken) storeRefreshTokenToDatabase(ctx context.Context, sub, jti string) error {
	return t.rdb.Set(ctx, fmt.Sprintf("%s:%s", TableName, jti), sub, 0).Err()
}

func (t *JWTToken) deleteRefreshTokenFromDatabase(ctx context.Context, jti string) error {
	return t.rdb.Del(ctx, fmt.Sprintf("%s:%s", TableName, jti)).Err()
}

func (t *JWTToken) findRefreshTokenFromDatabase(ctx context.Context, jti string) (sub string, err error) {
	sub, err = t.rdb.Get(ctx, fmt.Sprintf("%s:%s", TableName, jti)).Result()
	if errors.Is(err, redis.Nil) {
		err = ErrTokenAlreadyRefreshed
		return
	}
	return
}

func (t *JWTToken) findAllRefreshTokensFromDatabase(ctx context.Context) ([]RefreshToken, error) {

	tokens := make([]RefreshToken, 0)

	keys, err := t.rdb.Keys(ctx, fmt.Sprintf("%s:*", TableName)).Result()
	if err != nil {
		return tokens, err
	}

	for _, key := range keys {

		sub, err := t.rdb.Get(ctx, key).Result()
		if err != nil {
			return tokens, err
		}

		jti := strings.Split(key, ":")[1]
		tokens = append(tokens, RefreshToken{
			Subject: sub,
			JTI:     jti,
		})
	}

	return tokens, nil
}

func (t *JWTToken) initCachedRefreshTokens(ctx context.Context) (err error) {

	refreshTokens = make(map[string]string)

	cachedRefreshTokens, err := t.findAllRefreshTokensFromDatabase(ctx)
	if err != nil {
		return
	}

	for _, token := range cachedRefreshTokens {
		refreshTokens[token.JTI] = token.Subject
	}

	return
}

func (t *JWTToken) VerifyToken(authToken string) (*Claims, error) {

	token, err := jwt.ParseWithClaims(authToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return t.parseToken(token)
	})

	if err != nil {

		var ve *jwt.ValidationError
		if errors.As(err, &ve) {
			if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
				return nil, ErrExpiredToken
			}
		}

		return nil, ErrUnauthorized
	}

	if token.Valid {
		return token.Claims.(*Claims), nil
	} else {
		return nil, ErrUnauthorized
	}
}

func (t *JWTToken) storeRefreshToken(ctx context.Context, sub string) (jti string, err error) {
	jti, err = t.generateRandomString(32)
	if err != nil {
		return
	}

	for refreshTokens[jti] != "" {
		jti, err = t.generateRandomString(32)
		if err != nil {
			return
		}
	}

	err = t.storeRefreshTokenToDatabase(ctx, sub, jti)
	if err != nil {
		return
	}

	refreshTokens[jti] = sub

	return
}

func (t *JWTToken) DeleteRefreshToken(ctx context.Context, sub, jti string) (err error) {

	sub, err = t.findRefreshTokenFromDatabase(ctx, jti)
	if err != nil {
		return
	}

	refreshToken := RefreshToken{
		Subject: sub,
		JTI:     jti,
	}

	if refreshToken.JTI != jti {
		return ErrRefreshTokenNotFoundInDatabase
	} else {
		err = t.deleteRefreshTokenFromDatabase(ctx, jti)
		if err != nil {
			return
		}

		delete(refreshTokens, jti)
	}

	return
}

func (t *JWTToken) checkRefreshToken(jti string) bool {
	return refreshTokens[jti] != ""
}

func (t *JWTToken) generateCSRFSecret() (string, error) {
	return t.generateRandomString(32)
}

func (t *JWTToken) GenerateToken(ctx context.Context, userID string, sub string) (accessToken, refreshToken, csrfSecret string, expiresAt int64, err error) {

	// generate the csrf secret
	csrfSecret, err = t.generateCSRFSecret()
	if err != nil {
		return
	}

	// generate the refresh token
	refreshToken, err = t.createRefreshToken(ctx, sub, csrfSecret)

	// generate the auth token
	accessToken, expiresAt, err = t.createAccessToken(userID, sub, csrfSecret)
	if err != nil {
		return
	}

	return
}

func (t *JWTToken) createAccessToken(userID string, sub string, csrfSecret string) (authTokenString string, authTokenExp int64, err error) {

	authTokenExp = time.Now().Add(t.accessTokenValidTime).Unix()
	authClaims := Claims{
		UserID: userID,
		Csrf:   csrfSecret,
		StandardClaims: jwt.StandardClaims{
			Subject:   sub,
			ExpiresAt: authTokenExp,
		},
	}

	authTokenString, err = t.sign(authClaims)

	return
}

func (t *JWTToken) RenewToken(ctx context.Context, oldAccessTokenString string, oldRefreshTokenString, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, expiresAt int64, userId string, err error) {

	// first, check that a csrf token was provided
	if oldCsrfSecret == "" {
		fmt.Println("No CSRF token!")
		err = ErrUnauthorized
		return
	}

	// now, check that it matches what's in the auth token claims
	authToken, err := jwt.ParseWithClaims(oldAccessTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return t.parseToken(token)
	})

	authTokenClaims, ok := authToken.Claims.(*Claims)
	if !ok {
		return
	}

	if oldCsrfSecret != authTokenClaims.Csrf {
		fmt.Println("CSRF token doesn't match jwt!")
		err = ErrUnauthorized
		return
	}

	// next, check the auth token in a stateless manner
	if authToken.Valid {
		fmt.Println("Auth token is valid")
		// auth token has not expired
		// we need to return the csrf secret bc that's what the function calls for
		newCsrfSecret = authTokenClaims.Csrf

		// update the exp of refresh token string, but don't save to the db
		// we don't need to check if our refresh token is valid here
		// because we aren't renewing the auth token, the auth token is already valid
		newRefreshTokenString, err = t.updateRefreshTokenExp(ctx, oldRefreshTokenString)
		newAuthTokenString = oldAccessTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		fmt.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			fmt.Println("Auth token is expired")
			// auth token is expired
			newAuthTokenString, newCsrfSecret, expiresAt, userId, err = t.updateAccessToken(ctx, oldRefreshTokenString, oldAccessTokenString)
			if err != nil {
				return
			}

			// update the exp of refresh token string
			newRefreshTokenString, err = t.updateRefreshTokenExp(ctx, oldRefreshTokenString)
			if err != nil {
				return
			}

			// update the csrf string of the refresh token
			newRefreshTokenString, err = t.updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			if err != nil {
				return
			}

			return
		} else {
			fmt.Println("Error in auth token")
			err = ErrUnauthorized
			return
		}
	} else {
		fmt.Println("Error in auth token")
		err = ErrUnauthorized
		return
	}

	// if we get here, there was some error validating the token
	err = ErrUnauthorized
	return
}

func (t *JWTToken) parseToken(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	var key interface{}

	switch t.algorithm {
	case jwt.SigningMethodRS256:
		key = verifyKey
	case jwt.SigningMethodHS256:
		key = []byte(t.secretKey)
	}

	return key, nil
}

func (t *JWTToken) updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return t.parseToken(token)
	})
	if err != nil {
		return
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*RefreshTokenClaims)
	if !ok {
		return
	}

	refreshClaims := RefreshTokenClaims{
		Csrf: newCsrfString,
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id, // jti
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
	}

	newRefreshTokenString, err = t.sign(refreshClaims)
	return
}

func (t *JWTToken) updateAccessToken(ctx context.Context, refreshTokenString string, oldAccessToken string) (newAccessToken, csrfSecret string, expiresAt int64, userId string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return t.parseToken(token)
	})
	if err != nil {
		return
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*RefreshTokenClaims)
	if !ok {
		err = ErrReadingJWTClaims
		return
	}

	// check if the refresh token has been revoked
	if t.checkRefreshToken(refreshTokenClaims.StandardClaims.Id) {
		// the refresh token has not been revoked
		// has it expired?
		if refreshToken.Valid {
			// nope, the refresh token has not expired
			// issue a new auth token
			accessToken, _ := jwt.ParseWithClaims(oldAccessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				return t.parseToken(token)
			})

			oldAuthTokenClaims, ok := accessToken.Claims.(*Claims)
			if !ok {
				err = ErrReadingJWTClaims
				return
			}

			// our policy is to regenerate the csrf secret for each new auth token
			csrfSecret, err = t.generateCSRFSecret()
			if err != nil {
				return
			}

			userId = oldAuthTokenClaims.UserID

			newAccessToken, expiresAt, err = t.createAccessToken(oldAuthTokenClaims.UserID, oldAuthTokenClaims.StandardClaims.Subject, csrfSecret)

			return
		} else {
			fmt.Println("Refresh token has expired!")
			// the refresh token has expired!
			// Revoke the token in our db and require the user to fmtin again
			err = t.DeleteRefreshToken(ctx, refreshTokenClaims.Subject, refreshTokenClaims.StandardClaims.Id)
			if err != nil {
				return
			}
			err = ErrUnauthorized
			return
		}
	} else {
		fmt.Println("Refresh token has been revoked!")
		// the refresh token has been revoked!
		err = ErrUnauthorized
		return
	}
}

func (t *JWTToken) sign(claims jwt.Claims) (string, error) {
	// create a signer
	token := jwt.NewWithClaims(t.algorithm, claims)

	var tokenString string
	var err error

	// generate the token string
	switch t.algorithm {
	case jwt.SigningMethodRS256:
		tokenString, err = token.SignedString(signKey)
		break
	case jwt.SigningMethodHS256:
		tokenString, err = token.SignedString([]byte(t.secretKey))
		break
	}

	return tokenString, err
}

func (t *JWTToken) updateRefreshTokenExp(ctx context.Context, oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return t.parseToken(token)
	})
	if err != nil {
		return
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*RefreshTokenClaims)
	if !ok {
		return
	}

	err = t.DeleteRefreshToken(ctx, oldRefreshTokenClaims.Subject, oldRefreshTokenClaims.StandardClaims.Id)
	if err != nil {
		return
	}

	refreshTokenExp := time.Now().Add(t.refreshTokenValidTime).Unix()

	refreshJti, err := t.storeRefreshToken(ctx, oldRefreshTokenClaims.StandardClaims.Subject)
	if err != nil {
		return
	}

	refreshClaims := RefreshTokenClaims{
		Csrf: oldRefreshTokenClaims.Csrf,
		StandardClaims: jwt.StandardClaims{
			Id:        refreshJti, // jti
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
	}

	newRefreshTokenString, err = t.sign(refreshClaims)

	return
}

func (t *JWTToken) createRefreshToken(ctx context.Context, sub string, csrfString string) (refreshTokenString string, err error) {

	refreshTokenExp := time.Now().Add(t.refreshTokenValidTime).Unix()

	refreshJti, err := t.storeRefreshToken(ctx, sub)
	if err != nil {
		return
	}

	refreshClaims := &RefreshTokenClaims{
		Csrf: csrfString,
		StandardClaims: jwt.StandardClaims{
			Id:        refreshJti, // jti
			Subject:   sub,
			ExpiresAt: refreshTokenExp,
		},
	}

	refreshTokenString, err = t.sign(refreshClaims)
	return
}

func (t *JWTToken) grabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return "", ErrFetchingJWTClaims
	})
	authTokenClaims, ok := authToken.Claims.(*Claims)
	if !ok {
		return "", ErrFetchingJWTClaims
	}

	return authTokenClaims.StandardClaims.Subject, nil
}

func (t *JWTToken) revokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return t.parseToken(token)
	})
	if err != nil {
		return ErrParsingRefreshTokenWithClaims
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*RefreshTokenClaims)
	if !ok {
		return ErrReadingRefreshTokenClaims
	}

	err = t.DeleteRefreshToken(ctx, refreshTokenClaims.Subject, refreshTokenClaims.StandardClaims.Id)
	if err != nil {
		return err
	}

	return nil
}

func (t *JWTToken) generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (t *JWTToken) generateRandomString(s int) (string, error) {
	b, err := t.generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}
