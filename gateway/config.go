// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/url"
	"os"
)

type config struct {
	bind           string
	allowLocal     bool
	mode           string
	relayURL       string
	cloudURL       string
	nodeID         string
	managementFile string
	tokenFile      string
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("service URL must contain only an HTTP or HTTPS origin")
	}
	u.Path = ""
	return u, nil
}

// Read credentials only for the current operation. Never include file contents in errors.
func readSecret(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open credential file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("credential path must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("credential file must be readable only by its owner")
	}
	if info.Size() > 16384 {
		return nil, errors.New("credential file is too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, errors.New("cannot read credential file")
	}
	if len(b) > 16384 {
		clear(b)
		return nil, errors.New("credential file is too large")
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 {
		return nil, errors.New("credential file is empty")
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			clear(b)
			return nil, errors.New("credential contains invalid characters")
		}
	}
	return b, nil
}

func loadStatic(path string) ([32]byte, error) {
	defer os.Unsetenv("UC_RELAY_TOKEN")
	var b []byte
	if path != "" {
		var err error
		b, err = readSecret(path)
		if err != nil {
			return [32]byte{}, err
		}
	} else {
		b = []byte(os.Getenv("UC_RELAY_TOKEN"))
	}
	defer clear(b)
	if !validStatic(b) {
		return [32]byte{}, errors.New("static token must contain 32 to 512 visible ASCII characters")
	}
	return sha256.Sum256(b), nil
}
func validStatic(b []byte) bool {
	if len(b) < 32 || len(b) > 512 {
		return false
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
