package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Provider struct {
	Issuer      string
	ClientID    string
	privKey     *rsa.PrivateKey
	pubKey      *rsa.PublicKey
	tempStorage map[string]struct {
		UserInfo UserInfo
		Nonce    string
	}
}

type UserInfo struct {
	Sub    string   `json:"sub"`
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

func NewProvider(issuer, clientID string) *Provider {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Provider{
		Issuer:   issuer,
		ClientID: clientID,
		privKey:  privKey,
		pubKey:   &privKey.PublicKey,
		tempStorage: make(map[string]struct {
			UserInfo UserInfo
			Nonce    string
		}),
	}
}

func (p *Provider) HandleRoot(w http.ResponseWriter, r *http.Request) {

	// if code is not in the url, redirect to discovery endpoint
	if r.URL.Query().Get("code") == "" {
		http.Redirect(w, r, p.Issuer+"/.well-known/openid-configuration", http.StatusFound)
		return
	}

	// if code is in the url, continue to HandleToken
	p.HandleToken(w, r)
}

func (p *Provider) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	// Log the request
	slog.Info("Discovery request", "url", r.URL.String())

	// Allow all origins
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	discovery := map[string]interface{}{
		"issuer":                 p.Issuer,
		"authorization_endpoint": p.Issuer + "/auth",
		"token_endpoint":         p.Issuer + "/token",
		"userinfo_endpoint":      p.Issuer + "/userinfo",
		"jwks_uri":               p.Issuer + "/jwks",
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"claims_supported": []string{
			"aud", "email", "email_verified", "exp",
			"iat", "iss", "locale", "name", "sub",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (p *Provider) HandleAuth(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	// Log the request
	slog.Info("Auth request", "url", r.URL.String(), "nonce", nonce, "state", state, "redirect_uri", redirectURI)

	// Define default values
	defaultValues := UserInfo{
		Name:   "John Doe",
		Email:  "john@example.com",
		Groups: []string{"users", "developers"},
	}

	// Try to get values from cookie
	if cookie, err := r.Cookie("user_settings"); err == nil {
		jsonData, _ := base64.StdEncoding.DecodeString(cookie.Value)
		json.Unmarshal(jsonData, &defaultValues)
	}

	tmpl := template.Must(template.New("auth").Parse(`
		<html>
			<body>
				<h1>Fake OIDC Provider</h1>
				<form method="POST">
					<input type="hidden" name="nonce" value="{{.Nonce}}">
					<input type="hidden" name="state" value="{{.State}}">
					<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
					<label>Name: <input type="text" name="name" value="{{.DefaultValues.Name}}"></label><br>
					<label>Email: <input type="email" name="email" value="{{.DefaultValues.Email}}"></label><br>
					<label>Groups (comma-separated): <input type="text" name="groups" value="{{.Groups}}"></label><br>
					<input type="submit" value="Authorize">
				</form>
			</body>
		</html>
	`))

	if r.Method == "GET" {
		tmpl.Execute(w, map[string]interface{}{
			"Nonce":         nonce,
			"State":         state,
			"RedirectURI":   redirectURI,
			"DefaultValues": defaultValues,
			"Groups":        strings.Join(defaultValues.Groups, ","),
		})
		return
	}

	if r.Method == "POST" {
		r.ParseForm()
		userInfo := UserInfo{
			Sub:    "user123",
			Name:   r.FormValue("name"),
			Email:  r.FormValue("email"),
			Groups: strings.Split(r.FormValue("groups"), ","),
		}

		// Save user settings in a cookie
		jsonData, _ := json.Marshal(userInfo)
		encodedData := base64.StdEncoding.EncodeToString(jsonData)
		http.SetCookie(w, &http.Cookie{
			Name:    "user_settings",
			Value:   encodedData,
			Expires: time.Now().Add(30 * 24 * time.Hour), // Cookie expires in 30 days
			Path:    "/",
		})

		code := generateRandomString(32)
		p.storeTempUserInfo(code, userInfo, r.FormValue("nonce"))

		redirectURL := r.FormValue("redirect_uri") + "?code=" + code
		if state := r.FormValue("state"); state != "" {
			redirectURL += "&state=" + state
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	userInfo, nonce, ok := p.retrieveTempUserInfo(code)
	if !ok {
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	// Log the request
	slog.Info("Token request", "code", code, "nonce", nonce, "userInfo", userInfo)

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            p.Issuer,
		"sub":            userInfo.Sub,
		"aud":            p.ClientID,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"name":           userInfo.Name,
		"email":          userInfo.Email,
		"email_verified": true,
		"groups":         userInfo.Groups,
		"nonce":          nonce,
	})

	idTokenString, _ := idToken.SignedString(p.privKey)

	accessToken := generateRandomString(32)

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *Provider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return p.pubKey, nil
	})
	if err != nil {
		slog.Error("Error parsing token", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	userInfo := UserInfo{
		Sub:    claims["sub"].(string),
		Name:   claims["name"].(string),
		Email:  claims["email"].(string),
		Groups: interfaceSliceToStringSlice(claims["groups"].([]interface{})),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (p *Provider) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	// Allow all origins
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	n := base64.RawURLEncoding.EncodeToString(p.pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.pubKey.E)).Bytes())

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "1",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func interfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, len(slice))
	for i, v := range slice {
		result[i] = v.(string)
	}
	return result
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Add these functions to store and retrieve temporary user info
func (p *Provider) storeTempUserInfo(code string, userInfo UserInfo, nonce string) {
	// In a real implementation, you'd use a secure storage mechanism
	// For this example, we'll use a simple in-memory map
	// This is not thread-safe, so you'd need to add proper synchronization in a real scenario
	p.tempStorage[code] = struct {
		UserInfo UserInfo
		Nonce    string
	}{userInfo, nonce}
}

func (p *Provider) retrieveTempUserInfo(code string) (UserInfo, string, bool) {
	if info, ok := p.tempStorage[code]; ok {
		delete(p.tempStorage, code)
		return info.UserInfo, info.Nonce, true
	}
	return UserInfo{}, "", false
}

// Add this method to the UserInfo struct
func (u *UserInfo) GroupsString() string {
	return strings.Join(u.Groups, ",")
}
