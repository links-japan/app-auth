package auth

import (
	"context"
	"encoding/json"
	"github.com/go-redis/redis/v8"
	lru "github.com/hashicorp/golang-lru"
)

type Cache interface {
	Get(ctx context.Context, key string) (*User, error)
	Set(ctx context.Context, key string, user *User) error
	Remove(ctx context.Context, key string) error
	Exist(ctx context.Context, key string) (bool, error)
}

type SimpleCache struct {
	cache *lru.Cache
}

func NewSimpleCache(size int) (*SimpleCache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &SimpleCache{
		cache: cache,
	}, nil
}

func (s *SimpleCache) Get(ctx context.Context, key string) (*User, error) {
	val, ok := s.cache.Get(key)
	if !ok {
		return nil, nil
	}
	var user User
	err := json.Unmarshal(val.([]byte), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *SimpleCache) Set(ctx context.Context, key string, user *User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	s.cache.Add(key, data)
	return err
}

func (s *SimpleCache) Remove(ctx context.Context, key string) error {
	s.cache.Remove(key)
	return nil
}

func (s *SimpleCache) Exist(ctx context.Context, key string) (bool, error) {
	_, ok := s.cache.Get(key)
	return ok, nil
}

func NewRedisCache(addr string) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	return &RedisCache{
		rdb,
	}
}

type RedisCache struct {
	rdb *redis.Client
}

func (r *RedisCache) Get(ctx context.Context, key string) (*User, error) {
	val, err := r.rdb.HGet(ctx, "user:", key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var user User
	err = json.Unmarshal([]byte(val), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *RedisCache) Set(ctx context.Context, key string, user *User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	_, err = r.rdb.HSet(ctx, "user:", key, string(data)).Result()
	return err
}

func (r *RedisCache) Remove(ctx context.Context, key string) error {
	_, err := r.rdb.HDel(ctx, "user:", key).Result()
	return err
}

func (r *RedisCache) Exist(ctx context.Context, key string) (bool, error) {
	return r.rdb.HExists(ctx, "user:", key).Result()
}
