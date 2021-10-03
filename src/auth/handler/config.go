package handler

import (
	"os"
)

type config struct {
	hmacKey string
}

// NewConfigFromEnv -
func NewConfigFromEnv() *config {

	return &config{
		hmacKey: os.Getenv("HMAC_KEY"),
	}
}
