package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

// xoauth2Client implements the SASL XOAUTH2 mechanism for IMAP.
// Format: "user=<username>\x01auth=Bearer <token>\x01\x01"
type xoauth2Client struct {
	username string
	token    string
}

func newXOAuth2Client(username, token string) *xoauth2Client {
	return &xoauth2Client{username: username, token: token}
}

func (x *xoauth2Client) Start() (mech string, ir []byte, err error) {
	ir = []byte("user=" + x.username + "\x01auth=Bearer " + x.token + "\x01\x01")
	return "XOAUTH2", ir, nil
}

// Next is called if the server sends a challenge (an error JSON on auth failure).
// Returning empty bytes acknowledges the error so the server can reply with NO.
func (x *xoauth2Client) Next(_ []byte) ([]byte, error) {
	return []byte{}, nil
}

// TokenSource fetches and caches a Google OAuth2 access token.
// Multiple goroutines may call Token() concurrently; refresh is serialized.
type TokenSource struct {
	cfg       config.OAuth2Config
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewTokenSource(cfg config.OAuth2Config) *TokenSource {
	return &TokenSource{cfg: cfg}
}

// Token returns a valid access token, refreshing if it is absent or near expiry.
func (ts *TokenSource) Token() (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.token != "" && time.Now().Before(ts.expiresAt.Add(-60*time.Second)) {
		return ts.token, nil
	}
	return ts.refresh()
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (ts *TokenSource) refresh() (string, error) {
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {ts.cfg.ClientID},
		"client_secret": {ts.cfg.ClientSecret},
		"refresh_token": {ts.cfg.RefreshToken},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return "", fmt.Errorf("token refresh: %v", err)
	}
	defer resp.Body.Close()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %v", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token refresh error %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}

	ts.token = tr.AccessToken
	ts.expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return ts.token, nil
}
