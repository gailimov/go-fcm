package fcm

import (
	"context"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const firebaseScope = "https://www.googleapis.com/auth/firebase.messaging"

type tokenProvider struct {
	tokenSource oauth2.TokenSource
}

func newTokenProvider(jsonKey []byte) (*tokenProvider, error) {
	cfg, err := google.JWTConfigFromJSON(jsonKey, firebaseScope)
	if err != nil {
		return nil, errors.Wrapf(err, "fcm: failed to get JWT config for the firebase.messaging scope")
	}

	ts := cfg.TokenSource(context.Background())
	return &tokenProvider{
		tokenSource: ts,
	}, nil
}

// token is safe for use from multiple go routines. It will request a token if
// one does not exist or is expired.
func (src *tokenProvider) token() (string, error) {
	token, err := src.tokenSource.Token()
	if err != nil {
		return "", errors.Wrapf(err, "fcm: failed to generate Bearer token")
	}

	return token.AccessToken, nil
}
