package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

const (
	gmailScope      = "https://mail.google.com/"
	gmailAuthURL    = "https://accounts.google.com/o/oauth2/auth"
	gmailTokenURL   = "https://oauth2.googleapis.com/token"
	callbackAddr    = "localhost:8085"
	callbackPath    = "/callback"
	callbackRedirect = "http://" + callbackAddr + callbackPath
)

func runGmailAuth(cfg *config.Config) {
	var oauth *config.OAuth2Config
	switch {
	case cfg.Source.OAuth2 != nil:
		oauth = cfg.Source.OAuth2
	case cfg.Monitor != nil && cfg.Monitor.Source.OAuth2 != nil:
		oauth = cfg.Monitor.Source.OAuth2
	default:
		log.Fatal("no oauth2 credentials found — add source.oauth2.client_id/client_secret or monitor.source.oauth2.client_id/client_secret")
	}
	if oauth.ClientID == "" || oauth.ClientSecret == "" {
		log.Fatal("oauth2.client_id and client_secret must both be set")
	}

	params := url.Values{
		"client_id":     {oauth.ClientID},
		"redirect_uri":  {callbackRedirect},
		"response_type": {"code"},
		"scope":         {gmailScope},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	authURL := gmailAuthURL + "?" + params.Encode()

	codeCh := make(chan string, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		errParam := r.URL.Query().Get("error")
		if errParam != "" {
			http.Error(w, "Authorization denied: "+errParam, http.StatusBadRequest)
			codeCh <- ""
			return
		}
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "<html><body><h2>Authorization complete — you can close this tab.</h2></body></html>")
		codeCh <- code
	})

	ln, err := net.Listen("tcp", callbackAddr)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v\n(Is another process using port 8085?)", callbackAddr, err)
	}
	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("callback server: %v", err)
		}
	}()

	fmt.Println("Open the following URL in your browser to authorize Gmail access:")
	fmt.Println()
	fmt.Println(authURL)
	fmt.Println()
	fmt.Printf("Waiting for callback on http://%s%s ...\n", callbackAddr, callbackPath)

	code := <-codeCh

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)

	if code == "" {
		log.Fatal("authorization was denied or cancelled")
	}

	refreshToken, err := exchangeCode(oauth.ClientID, oauth.ClientSecret, code)
	if err != nil {
		log.Fatalf("token exchange failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Authorization successful!")
	fmt.Println()
	fmt.Println("Add the following line to your config under monitor.source.oauth2:")
	fmt.Println()
	fmt.Printf("  refresh_token: %q\n", refreshToken)
	fmt.Println()
}

type authTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func exchangeCode(clientID, clientSecret, code string) (string, error) {
	body := url.Values{
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {callbackRedirect},
		"grant_type":    {"authorization_code"},
	}
	resp, err := http.Post(gmailTokenURL, "application/x-www-form-urlencoded",
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", fmt.Errorf("HTTP request: %v", err)
	}
	defer resp.Body.Close()

	var tr authTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode response: %v", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("%s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.RefreshToken == "" {
		return "", fmt.Errorf("no refresh_token in response (did you use prompt=consent?)")
	}
	return tr.RefreshToken, nil
}
