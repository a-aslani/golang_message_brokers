package token

import (
	"context"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"strings"
)

type RedisRepository struct {
	rdb *redis.Client
}

var _ Repository = (*RedisRepository)(nil)

func NewRedisRepository(addr, pass string) *RedisRepository {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: pass,
		DB:       0,
	})
	return &RedisRepository{rdb}
}

func (r RedisRepository) StoreRefreshToken(ctx context.Context, sub, jti string) error {
	return r.rdb.Set(ctx, fmt.Sprintf("%s:%s", TableName, jti), sub, 0).Err()
}

func (r RedisRepository) DeleteRefreshToken(ctx context.Context, jti string) error {
	return r.rdb.Del(ctx, fmt.Sprintf("%s:%s", TableName, jti)).Err()
}

func (r RedisRepository) FindRefreshToken(ctx context.Context, jti string) (sub string, err error) {
	sub, err = r.rdb.Get(ctx, fmt.Sprintf("%s:%s", TableName, jti)).Result()
	if errors.Is(err, redis.Nil) {
		err = ErrTokenAlreadyRefreshed
		return
	}
	return
}

func (r RedisRepository) FindAllRefreshTokens(ctx context.Context) ([]RefreshToken, error) {
	tokens := make([]RefreshToken, 0)

	keys, err := r.rdb.Keys(ctx, fmt.Sprintf("%s:*", TableName)).Result()
	if err != nil {
		return tokens, err
	}

	for _, key := range keys {

		sub, err := r.rdb.Get(ctx, key).Result()
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
