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
	slog.Info("Initializing new OIDC provider", "issuer", issuer, "clientID", clientID)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("Failed to generate RSA private key", "error", err)
		return nil
	}
	slog.Info("Successfully generated RSA private key")
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
	slog.Info("HandleRoot called", "method", r.Method, "url", r.URL.String())
	if r.URL.Query().Get("code") == "" {
		slog.Info("No code found in URL, redirecting to discovery endpoint")
		http.Redirect(w, r, p.Issuer+"/.well-known/openid-configuration", http.StatusFound)
		return
	}

	slog.Info("Code found in URL, proceeding to HandleToken")
	p.HandleToken(w, r)
}

func (p *Provider) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	slog.Info("Discovery request received", "method", r.Method, "url", r.URL.String())

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
	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		slog.Error("Failed to encode discovery response", "error", err)
		http.Error(w, "Failed to encode discovery response", http.StatusInternalServerError)
	}
}

func (p *Provider) HandleAuth(w http.ResponseWriter, r *http.Request) {
	slog.Info("HandleAuth called", "method", r.Method, "url", r.URL.String())
	nonce := r.URL.Query().Get("nonce")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	slog.Info("Auth request parameters", "nonce", nonce, "state", state, "redirect_uri", redirectURI)

	defaultValues := UserInfo{
		Name:   "John Doe",
		Email:  "john@example.com",
		Groups: []string{"users", "developers"},
	}

	if cookie, err := r.Cookie("user_settings"); err == nil {
		jsonData, err := base64.StdEncoding.DecodeString(cookie.Value)
		if err == nil {
			slog.Info("Loaded user settings from cookie", "user_settings", string(jsonData))
			json.Unmarshal(jsonData, &defaultValues)
		} else {
			slog.Warn("Failed to decode user settings cookie", "error", err)
		}
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
		if err := tmpl.Execute(w, map[string]interface{}{
			"Nonce":         nonce,
			"State":         state,
			"RedirectURI":   redirectURI,
			"DefaultValues": defaultValues,
			"Groups":        strings.Join(defaultValues.Groups, ","),
		}); err != nil {
			slog.Error("Failed to execute auth template", "error", err)
			http.Error(w, "Failed to render authorization page", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == "POST" {
		slog.Info("Processing POST request for HandleAuth")
		r.ParseForm()
		userInfo := UserInfo{
			Sub:    "user123",
			Name:   r.FormValue("name"),
			Email:  r.FormValue("email"),
			Groups: strings.Split(r.FormValue("groups"), ","),
		}

		slog.Info("User info received from form", "userInfo", userInfo)

		jsonData, err := json.Marshal(userInfo)
		if err != nil {
			slog.Error("Failed to marshal user info", "error", err)
			http.Error(w, "Failed to process user information", http.StatusInternalServerError)
			return
		}
		encodedData := base64.StdEncoding.EncodeToString(jsonData)
		http.SetCookie(w, &http.Cookie{
			Name:    "user_settings",
			Value:   encodedData,
			Expires: time.Now().Add(30 * 24 * time.Hour),
			Path:    "/",
		})

		slog.Info("User settings saved in cookie", "encodedData", encodedData)

		code := generateRandomString(32)
		p.storeTempUserInfo(code, userInfo, r.FormValue("nonce"))

		slog.Info("Generated authorization code", "code", code)

		redirectURL := r.FormValue("redirect_uri") + "?code=" + code
		if state := r.FormValue("state"); state != "" {
			redirectURL += "&state=" + state
		}
		slog.Info("Redirecting to", "redirectURL", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	slog.Info("HandleToken called", "method", r.Method, "url", r.URL.String())
	code := r.FormValue("code")
	userInfo, nonce, ok := p.retrieveTempUserInfo(code)
	if !ok {
		slog.Warn("Invalid authorization code", "code", code)
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

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

	idTokenString, err := idToken.SignedString(p.privKey)
	if err != nil {
		slog.Error("Failed to sign ID token", "error", err)
		http.Error(w, "Failed to generate ID token", http.StatusInternalServerError)
		return
	}

	slog.Info("Generated ID token", "idToken", idTokenString)

	accessToken := generateRandomString(32)
	slog.Info("Generated access token", "accessToken", accessToken)

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode token response", "error", err)
		http.Error(w, "Failed to encode token response", http.StatusInternalServerError)
	}
}

func (p *Provider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	slog.Info("HandleUserInfo called", "method", r.Method, "url", r.URL.String())
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	slog.Info("Parsing token", "tokenString", tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return p.pubKey, nil
	})
	if err != nil {
		slog.Error("Error parsing token", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		slog.Error("Invalid token claims")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	slog.Info("Token parsed successfully", "claims", claims)

	userInfo := UserInfo{
		Sub:    claims["sub"].(string),
		Name:   claims["name"].(string),
		Email:  claims["email"].(string),
		Groups: interfaceSliceToStringSlice(claims["groups"].([]interface{})),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		slog.Error("Failed to encode user info response", "error", err)
		http.Error(w, "Failed to encode user info response", http.StatusInternalServerError)
	}
}

func (p *Provider) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	slog.Info("HandleJWKS called", "method", r.Method, "url", r.URL.String())
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
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		slog.Error("Failed to encode JWKS response", "error", err)
		http.Error(w, "Failed to encode JWKS response", http.StatusInternalServerError)
	}
}

func interfaceSliceToStringSlice(slice []interface{}) []string {
	slog.Info("Converting interface slice to string slice", "slice", slice)
	result := make([]string, len(slice))
	for i, v := range slice {
		str, ok := v.(string)
		if !ok {
			slog.Warn("Failed to convert interface to string", "value", v)
			result[i] = ""
		} else {
			result[i] = str
		}
	}
	return result
}

func generateRandomString(length int) string {
	slog.Info("Generating random string", "length", length)
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random string", "error", err)
		return ""
	}
	result := base64.RawURLEncoding.EncodeToString(b)
	slog.Info("Generated random string", "result", result)
	return result
}

func (p *Provider) storeTempUserInfo(code string, userInfo UserInfo, nonce string) {
	slog.Info("Storing temporary user info", "code", code, "userInfo", userInfo, "nonce", nonce)
	p.tempStorage[code] = struct {
		UserInfo UserInfo
		Nonce    string
	}{userInfo, nonce}
}

func (p *Provider) retrieveTempUserInfo(code string) (UserInfo, string, bool) {
	slog.Info("Retrieving temporary user info", "code", code)
	if info, ok := p.tempStorage[code]; ok {
		slog.Info("Successfully retrieved temporary user info", "code", code, "userInfo", info.UserInfo, "nonce", info.Nonce)
		delete(p.tempStorage, code)
		return info.UserInfo, info.Nonce, true
	}
	slog.Warn("Failed to retrieve temporary user info", "code", code)
	return UserInfo{}, "", false
}

func (u *UserInfo) GroupsString() string {
	slog.Info("Converting groups to string", "groups", u.Groups)
	return strings.Join(u.Groups, ",")
}
