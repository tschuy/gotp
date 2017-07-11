package gpg

import (
	"errors"
	"os"

	"golang.org/x/crypto/openpgp"
)

var prefix = os.Getenv("HOME")
var gpgHome = getEnvDefault("GNUPGHOME", prefix)
var secretKeyring = gpgHome + "/.gnupg/secring.gpg"
var publicKeyring = gpgHome + "/.gnupg/pubring.gpg"

func getEnvDefault(env string, def string) string {
	if s := os.Getenv(env); s != "" {
		return s
	}
	return def
}

// returns the private gnupg keystore from disk
func GetPrivateKeyRing() (*openpgp.EntityList, error) {
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return nil, err
	}
	defer keyringFileBuffer.Close()

	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return nil, err
	}

	return &entityList, nil
}

// returns the public gnupg keystore from disk
func GetPublicKeyRing() (*openpgp.EntityList, error) {
	var entityList openpgp.EntityList

	// Open the public key file
	keyringFileBuffer, err := os.Open(publicKeyring)
	if err != nil {
		if _, err := os.Stat(gpgHome + "/.gnupg/pubring.kbx"); !os.IsNotExist(err) {
			return nil, errors.New("not compatible with kbx keyring")
		}
		return nil, err
	}
	defer keyringFileBuffer.Close()

	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return nil, err
	}

	return &entityList, nil
}
