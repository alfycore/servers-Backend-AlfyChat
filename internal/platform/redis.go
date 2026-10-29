// ==========================================
// ALFYCHAT - REDIS CLIENT
// Copié uniquement dans les services qui utilisent Redis.
// ==========================================

package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func redisOptions() (*redis.Options, error) {
	var opts *redis.Options
	if u := Env("REDIS_URL", ""); u != "" {
		var err error
		if opts, err = redis.ParseURL(u); err != nil {
			return nil, err
		}
	} else {
		opts = &redis.Options{
			Addr:     fmt.Sprintf("%s:%d", Env("REDIS_HOST", "localhost"), EnvInt("REDIS_PORT", 6379)),
			Password: Env("REDIS_PASSWORD", ""),
		}
	}
	opts.DialTimeout = 5 * time.Second
	return opts, nil
}

// OpenRedis se connecte et vérifie la connexion par un PING (5 s max).
func OpenRedis() (*redis.Client, error) {
	opts, err := redisOptions()
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

// NewRedis crée le client sans le tester : il se reconnecte seul, comme
// ioredis, et le service démarre même si Redis est momentanément absent.
func NewRedis() (*redis.Client, error) {
	opts, err := redisOptions()
	if err != nil {
		return nil, err
	}
	opts.MaxRetries = -1
	return redis.NewClient(opts), nil
}
