package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:8080")
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: "mock-client-id"})

	// Configure the OAuth2 config
	config := oauth2.Config{
		ClientID:     "mock-client-id",
		ClientSecret: "your-client-secret", // Not used by the fake provider, but required by oauth2 package
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8081/callback",
	}

	// Set up a simple web server to handle the callback
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		url := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rawToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Invalid token type", http.StatusInternalServerError)
			return
		}

		jwt, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Info("JWT", "jwt", jwt)

		fmt.Fprintf(w, "JWT: %s", rawToken)
	})

	// Start the web server
	log.Println("Starting client on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
