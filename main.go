package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/iwanhae/fakeoidcprovider/config"
	"github.com/iwanhae/fakeoidcprovider/oidc"
)

type Config struct {
	Debug    bool   `mapstructure:"debug"`
	Port     string `mapstructure:"port"`
	Issuer   string `mapstructure:"issuer"`
	ClientID string `mapstructure:"client_id"`
}

func main() {
	ctx := context.Background()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	var cfg Config
	config.Load(ctx, "oidc", &cfg)

	if cfg.Debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	}

	slog.InfoContext(ctx, "config loaded", "config", cfg)

	provider := oidc.NewProvider(cfg.Issuer, cfg.ClientID)
	http.HandleFunc("/", provider.HandleRoot)
	http.HandleFunc("/.well-known/openid-configuration", provider.HandleDiscovery)
	http.HandleFunc("/auth", provider.HandleAuth)
	http.HandleFunc("/token", provider.HandleToken)
	http.HandleFunc("/userinfo", provider.HandleUserInfo)
	http.HandleFunc("/jwks", provider.HandleJWKS) // Add this line

	slog.InfoContext(ctx, "Starting server", "port", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		slog.ErrorContext(ctx, "Server error", "error", err)
		os.Exit(1)
	}
}
