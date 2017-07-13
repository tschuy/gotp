package token

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"camlistore.org/pkg/misc/gpgagent"
	"golang.org/x/crypto/openpgp"

	"github.com/tschuy/gotp/gpg"
)

// TokenDir is the directory where encrypted json tokens are stored
var TokenDir = os.Getenv("HOME") + "/.otptokens"

type JsonToken struct {
	Fingerprints []string
	Token        string
}

type Token struct {
	Name            string
	Fingerprints    [][]byte
	StrFingerprints []string
	EncryptedToken  []byte
	Token           string
	Hotp            bool
	Counter         uint64
}

func Verify(secret string) error {
	_, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return errors.New("invalid secret (was not base32!)")
	}
	return nil
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

// DeleteToken : delete token tkName from disk
func DeleteToken(tkName string) error {
	path := TokenDir + "/" + tkName
	_, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// ReadToken : read tkName from inside tokenstore dir and
// unmarshal info to return a token with EncryptedToken
// and Fingerprints info
func ReadToken(tkName string) (Token, error) {
	var jk JsonToken
	var tk Token

	f, err := ioutil.ReadFile(TokenDir + "/" + tkName + "/token.json")
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
	tk.StrFingerprints = jk.Fingerprints

	encToken, err := base64.StdEncoding.DecodeString(jk.Token)
	if err != nil {
		return tk, err
	}

	tk.EncryptedToken = encToken
	tk.Name = tkName

	tokenBytes, err := Decrypt(encToken)
	if err != nil {
		return tk, err
	}

	tk.Token = string(tokenBytes)
	parts := strings.Split(tk.Token, ":")
	if len(parts) > 1 {
		counter, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return tk, err
		}
		tk.Counter = counter
		tk.Hotp = true
		tk.Token = parts[1]
	} else {
	}

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

// returns list of openpgp Entities from a list of fingerprints.
// Fingerprints are the full length fingerprint of individual gpg keys.
// Every primary key in the gpg store is examined.
// TODO examine child keys
func getKeys(fingerprints [][]byte, emails []string) ([]*openpgp.Entity, error) {
	m := make(map[[20]byte]bool) // fingerprints
	e := make(map[string]bool)   // emails
	var tmp [20]byte
	for _, fingerprint := range fingerprints {
		copy(tmp[:], fingerprint)
		m[tmp] = true
	}
	for _, email := range emails {
		e[email] = true
	}

	keyring, err := gpg.GetPublicKeyRing()
	if err != nil {
		return nil, err
	}

	// Encrypt message using public key
	var el []*openpgp.Entity

	for _, key := range *keyring {
		if key.PrimaryKey != nil {
			for _, v := range key.Identities {
				if e[v.UserId.Email] {
					el = append(el, key)
					continue
				}
			}
			if m[key.PrimaryKey.Fingerprint] {
				el = append(el, key)
			}
		}
	}
	return el, nil
}

// Takes token secret, name, and fingerprints of encrypting keys
// Find public keys needed, encrypt with all of them, and construct
// the token. Finally, write the token file.
func WriteToken(token string, name string, fingerprints []string, emails []string, hotp bool, counter uint64) error {
	var jk JsonToken
	byteFingerprints, err := hexStringsToByteSlices(fingerprints)
	if err != nil {
		return err
	}

	el, err := getKeys(byteFingerprints, emails)
	if err != nil {
		return err
	}

	if len(el) != len(fingerprints)+len(emails) {
		return errors.New("could not find keys for all requested fingerprints and emails")
	}

	var fps []string
	for _, key := range el {
		fps = append(fps, fmt.Sprintf("%x", key.PrimaryKey.Fingerprint))
	}
	// converts email addresses into tokens
	jk.Fingerprints = fps

	if hotp {
		token = strconv.FormatUint(counter, 10) + ":" + token
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

	err = os.MkdirAll(TokenDir+"/"+name, 0777)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(TokenDir+"/"+name+"/token.json", data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Decrypts encrypted []byte with any available pgp key
func Decrypt(encoded []byte) ([]byte, error) {
	keyring, err := gpg.GetPrivateKeyRing()
	if err != nil {
		return nil, err
	}

	encodedReader := bytes.NewReader(encoded)
	md, err := openpgp.ReadMessage(encodedReader, keyring, pr, nil)
	if err != nil {
		if strings.Contains(err.Error(), "PROGRESS need_entropy") {
			fmt.Print("gpg-agent needs more entropy; please try again!\n")
			os.Exit(1)
		}
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
