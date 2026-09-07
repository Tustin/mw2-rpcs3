package admin

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessValidator struct {
	teamDomain string
	audience   string
	client     *http.Client
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	expires    time.Time
}

func LocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			http.Error(w, "local admin access only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type certsResponse struct {
	Keys []struct {
		KID string `json:"kid"`
		KTY string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func NewAccessValidator(teamDomain, audience string) (*AccessValidator, error) {
	teamDomain = strings.TrimSuffix(strings.TrimSpace(teamDomain), "/")
	if teamDomain == "" || audience == "" {
		return nil, errors.New("Cloudflare Access team domain and audience are required")
	}
	if !strings.HasPrefix(teamDomain, "https://") {
		teamDomain = "https://" + teamDomain
	}
	return &AccessValidator{teamDomain: teamDomain, audience: audience, client: &http.Client{Timeout: 5 * time.Second}}, nil
}

func (v *AccessValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Cf-Access-Jwt-Assertion")
		if token == "" {
			http.Error(w, "Cloudflare Access assertion required", http.StatusUnauthorized)
			return
		}
		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, v.keyFunc(r.Context()),
			jwt.WithAudience(v.audience), jwt.WithIssuer(v.teamDomain), jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !parsed.Valid {
			http.Error(w, "invalid Cloudflare Access assertion", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *AccessValidator) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("JWT is missing kid")
		}
		keys, err := v.publicKeys(ctx, false)
		if err == nil {
			if key := keys[kid]; key != nil {
				return key, nil
			}
		}
		keys, err = v.publicKeys(ctx, true)
		if err != nil {
			return nil, err
		}
		key := keys[kid]
		if key == nil {
			return nil, fmt.Errorf("unknown JWT key %q", kid)
		}
		return key, nil
	}
}

func (v *AccessValidator) publicKeys(ctx context.Context, force bool) (map[string]*rsa.PublicKey, error) {
	v.mu.RLock()
	if !force && time.Now().Before(v.expires) && len(v.keys) > 0 {
		keys := v.keys
		v.mu.RUnlock()
		return keys, nil
	}
	v.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.teamDomain+"/cdn-cgi/access/certs", nil)
	if err != nil {
		return nil, err
	}
	response, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Cloudflare Access keys: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch Cloudflare Access keys: status %d", response.StatusCode)
	}
	var payload certsResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode Cloudflare Access keys: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, item := range payload.Keys {
		if item.KTY != "RSA" || item.KID == "" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(item.N)
		if err != nil {
			return nil, fmt.Errorf("decode key modulus: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(item.E)
		if err != nil {
			return nil, fmt.Errorf("decode key exponent: %w", err)
		}
		exponent := 0
		for _, value := range e {
			exponent = exponent<<8 | int(value)
		}
		keys[item.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	if len(keys) == 0 {
		return nil, errors.New("Cloudflare Access returned no RSA keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.expires = time.Now().Add(time.Hour)
	v.mu.Unlock()
	return keys, nil
}
