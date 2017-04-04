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

// ability to encrypt a file with one gpg key                 [:+1:]
// ability to encrypt a file with MULTIPLE gpg keys           [:+1:] -- [:-1:]
// ability to reference keys by id, not by including here     []
// cli to add a token (and have it automatically encrypted)   []
// nice listing of all added tokens                           []
// generate an OTP token from a TOTP token                    [:+1:]
// generate an OTP token from an HOTP token                    []

var prefix = os.Getenv("HOME")
var secretKeyring = prefix + "/.gnupg/secring.gpg"
var publicKeyring = prefix + "/.gnupg/pubring.gpg"

func pr(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	conn, err := gpgagent.NewGpgAgentConn()
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

func main() {
	os.Setenv("GPG_AGENT_INFO",
		"/run/user/"+strconv.FormatInt(int64(os.Getuid()), 10)+"/gnupg/S.gpg-agent:12345:1")
	myStr := "ZVB267QPFBAGROTDE6US5UN255A5BJAOKAJY2VMU3EZWNYCGKBLIVLJ3QB6N6GWR"
	encrypt(myStr) // saves myStr to test.gpg
	log.Println("Reading token from:", "test.gpg")
	res, err := decrypt()

	if err != nil {
		log.Fatal(err)
	}

	log.Print("secret otp key: ", res)

	totp := &otp.TOTP{Secret: res, IsBase32Secret: true}
	log.Print(totp.Get())
}

func decrypt() (string, error) {
	keyring, err := getKeyRing()

	if err != nil {
		log.Fatal(err)
	}

	f, _ := os.Open("test.gpg")
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

func encrypt(str string) {
	keyring, err := getKeyRing()
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt message using public key
	buf := new(bytes.Buffer)
	var el []*openpgp.Entity

	for _, key := range *keyring {
		if key.PrimaryKey != nil {
			el = append(el, key)
		}
	}

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
	ioutil.WriteFile("test.gpg", bytes, 0644)
}
