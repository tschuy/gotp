package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"camlistore.org/pkg/misc/gpgagent"
	"github.com/hgfischer/go-otp"

	"golang.org/x/crypto/openpgp"
)

var prefix = os.Getenv("HOME")
var secretKeyring = prefix + "/.gnupg/secring.gpg"
var publicKeyring = prefix + "/.gnupg/pubring.gpg"

func pr(keys []openpgp.Key, symmetric bool) ([]byte, error) {
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

func getKeyRing() (*openpgp.EntityList, error) {
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(os.Getenv("HOME") + "/.gnupg/secring.gpg")
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

func getPublicKeyRing() (*openpgp.EntityList, error) {
	var entityList openpgp.EntityList

	// Open the public key file
	keyringFileBuffer, err := os.Open(os.Getenv("HOME") + "/.gnupg/pubring.gpg")
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

func encryptKeys(fingerprints [][]byte) ([]*openpgp.Entity, error) {
	m := make(map[[20]byte]bool)
	var tmp [20]byte
	for _, fingerprint := range fingerprints {
		copy(tmp[:], fingerprint)
		m[tmp] = true
	}

	keyring, err := getPublicKeyRing()
	if err != nil {
		log.Fatal(err)
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

func main() {
	// horrible hack
	os.Setenv("GPG_AGENT_INFO",
		"/run/user/"+strconv.FormatInt(int64(os.Getuid()), 10)+"/gnupg/S.gpg-agent:12345:1")
	myStr := "ZVB267QPFBAGROTDE6US5UN255A5BJAOKAJY2VMU3EZWNYCGKBLIVLJ3QB6N6GWR"

	b1, err := hex.DecodeString("example1")
	if err != nil {
		log.Fatal(err)
	}
	b2, err := hex.DecodeString("example2")
	if err != nil {
		log.Fatal(err)
	}

	// encrypt a file using public keys from gpg keyring. identify keys to use
	// from fingerprints above.
	el, err := encryptKeys([][]byte{b1, b2})
	if err != nil {
		log.Fatal(err)
	}

	encrypt("test.gpg", myStr, el)

	// decrypt file, use result as TOTP token, and generate a token
	res, err := decrypt("test.gpg")

	if err != nil {
		log.Fatal(err)
	}

	log.Print("secret otp key: ", res)

	totp := &otp.TOTP{Secret: res, IsBase32Secret: true}
	fmt.Printf("test.gpg: %s\n", totp.Get())
}

func decrypt(fi string) (string, error) {
	keyring, err := getKeyRing()

	if err != nil {
		log.Fatal(err)
	}

	f, _ := os.Open(fi)
	md, err := openpgp.ReadMessage(f, keyring, pr, nil)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func encrypt(fi string, str string, el openpgp.EntityList) {
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, el, nil, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = w.Write([]byte(str))
	if err != nil {
		log.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		log.Fatal(err)
	}

	bytes, err := ioutil.ReadAll(buf)
	ioutil.WriteFile(fi, bytes, 0644)
}
