package token

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"camlistore.org/pkg/misc/gpgagent"
	"golang.org/x/crypto/openpgp"
)

var prefix = os.Getenv("HOME")
var gpgHome = getEnvDefault("GNUPGHOME", prefix)
var secretKeyring = gpgHome + "/.gnupg/secring.gpg"
var publicKeyring = gpgHome + "/.gnupg/pubring.gpg"
var tokenDir = prefix + "/.otptokens"

func getEnvDefault(env string, def string) string {
	if s := os.Getenv(env); s != "" {
		return s
	}
	return def
}

type JsonToken struct {
	Fingerprints []string
	Token        string
}

type Token struct {
	Name           string
	Fingerprints   [][]byte
	EncryptedToken []byte
	Token          string
}

// Converts a []string of hex strings into a [][]byte.
func hexStringsToByteSlices(strings []string) ([][]byte, error) {
	var byteslices [][]byte
	for _, str := range strings {
		b, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}
		byteslices = append(byteslices, b)
	}
	return byteslices, nil
}

// read token tkName from inside tokenstore dir.
// unmarshals info to return a token with EncryptedToken
// and Fingerprints info
func ReadToken(tkName string) (Token, error) {
	var jk JsonToken
	var tk Token

	f, err := ioutil.ReadFile(tokenDir + "/" + tkName + "/token.json")
	if err != nil {
		return tk, err
	}

	err = json.Unmarshal(f, &jk)
	if err != nil {
		return tk, err
	}

	fingerprints, err := hexStringsToByteSlices(jk.Fingerprints)
	if err != nil {
		return tk, err
	}
	tk.Fingerprints = fingerprints

	encToken, err := base64.StdEncoding.DecodeString(jk.Token)
	if err != nil {
		return tk, err
	}

	tk.EncryptedToken = encToken
	tk.Name = tkName

	return tk, nil
}

func pr(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	// password request function
	// returns a password for the openpgp.Encrypt
	conn, err := gpgagent.NewConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for _, key := range keys {
		// get passphrase for key from gpg-agent
		cacheId := strings.ToUpper(hex.EncodeToString(key.PublicKey.Fingerprint[:]))
		request := gpgagent.PassphraseRequest{CacheKey: cacheId}
		passphrase, err := conn.GetPassphrase(&request)
		if err != nil {
			return nil, err
		}

		// decrypt the key
		err = key.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return nil, err
		}
		return []byte(passphrase), nil
	}
	return nil, fmt.Errorf("Unable to find key")
}

// returns the private gnupg keystore from disk
func getPrivateKeyRing() (*openpgp.EntityList, error) {
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
func getPublicKeyRing() (*openpgp.EntityList, error) {
	var entityList openpgp.EntityList

	// Open the public key file
	keyringFileBuffer, err := os.Open(publicKeyring)
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

// returns list of openpgp Entities from a list of fingerprints.
// Fingerprints are the full length fingerprint of individual gpg keys.
// Every primary key in the gpg store is examined.
// TODO examine child keys
func keysFromPrints(fingerprints [][]byte) ([]*openpgp.Entity, error) {
	m := make(map[[20]byte]bool)
	var tmp [20]byte
	for _, fingerprint := range fingerprints {
		copy(tmp[:], fingerprint)
		m[tmp] = true
	}

	keyring, err := getPublicKeyRing()
	if err != nil {
		return nil, err
	}

	// Encrypt message using public key
	var el []*openpgp.Entity

	for _, key := range *keyring {
		if key.PrimaryKey != nil {
			if m[key.PrimaryKey.Fingerprint] {
				log.Printf("encrypting with key %x", key.PrimaryKey.Fingerprint)
				el = append(el, key)
			}
		}
	}
	return el, nil
}

// Takes token secret, name, and fingerprints of encrypting keys
// Find public keys needed, encrypt with all of them, and construct
// the token. Finally, write the token file.
func WriteToken(token string, name string, fingerprints []string) error {
	var jk JsonToken
	jk.Fingerprints = fingerprints
	byteFingerprints, err := hexStringsToByteSlices(fingerprints)
	if err != nil {
		return err
	}
	el, err := keysFromPrints(byteFingerprints)
	if err != nil {
		return err
	}
	encryptedToken, err := Encrypt([]byte(strings.TrimSpace(token)), el)
	if err != nil {
		return err
	}
	jk.Token = string(encryptedToken)

	data, err := json.Marshal(jk)
	if err != nil {
		return err
	}

	err = os.MkdirAll(tokenDir+"/"+name, 0777)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(tokenDir+"/"+name+"/token.json", data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Decrypts encrypted []byte with any available pgp key
func Decrypt(encoded []byte) ([]byte, error) {
	keyring, err := getPrivateKeyRing()
	if err != nil {
		return nil, err
	}

	encodedReader := bytes.NewReader(encoded)
	md, err := openpgp.ReadMessage(encodedReader, keyring, pr, nil)
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// encrypt and base64 encode a source []byte with all keys requested
func Encrypt(src []byte, el openpgp.EntityList) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, el, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(src)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	// base64 encode
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(bytes)))
	base64.StdEncoding.Encode(dst, bytes)
	return dst, nil
}
