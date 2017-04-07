package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/hgfischer/go-otp"

	"camlistore.org/pkg/misc/gpgagent"

	"golang.org/x/crypto/openpgp"
)

var prefix = os.Getenv("HOME")
var secretKeyring = prefix + "/.gnupg/secring.gpg"
var publicKeyring = prefix + "/.gnupg/pubring.gpg"

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

func fingerStringsToBytes(strings []string) [][]byte {
	var fingerprints [][]byte
	for _, print := range strings {
		b, err := hex.DecodeString(print)
		if err != nil {
			log.Fatal(err)
		}
		fingerprints = append(fingerprints, b)
	}
	return fingerprints
}

func readToken(dir string, tkName string) Token {
	f, err := ioutil.ReadFile(dir + "/" + tkName + "/token.json")
	if err != nil {
		log.Fatalf("could not read token: %s", err)
	}

	var jk JsonToken
	var tk Token

	err = json.Unmarshal(f, &jk)
	if err != nil {
		log.Fatal(err)
	}

	tk.Fingerprints = fingerStringsToBytes(jk.Fingerprints)

	encToken, err := base64.StdEncoding.DecodeString(jk.Token)
	if err != nil {
		log.Fatal(err)
	}

	tk.EncryptedToken = encToken
	tk.Name = tkName

	return tk
}

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

	if len(os.Args) > 1 {
		if os.Args[1] == "enroll" {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			writeToken(text, os.Args[2], os.Args[3:])
		}
		return
	}
	log.Print("Reading tokens from ./.tokens...")
	files, _ := ioutil.ReadDir("./.tokens")
	for _, f := range files {
		mode := f.Mode()
		if mode.IsDir() {
			tk := readToken("./.tokens", f.Name())
			decrypted, err := decrypt(tk.EncryptedToken)
			if err != nil {
				log.Fatal(err)
			}
			totp := &otp.TOTP{Secret: decrypted, IsBase32Secret: true}
			log.Printf("%s: %s", tk.Name, totp.Get())
		}
	}
}

func writeToken(token string, name string, fingerprints []string) {
	var jk JsonToken
	jk.Fingerprints = fingerprints
	el, err := encryptKeys(fingerStringsToBytes(fingerprints))
	if err != nil {
		log.Fatal(err)
	}
	jk.Token = encrypt(strings.TrimSpace(token), el)
	data, err := json.Marshal(jk)
	if err != nil {
		log.Fatal(err)
	}

	err = os.MkdirAll("./.tokens/"+name, 0777)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("./.tokens/"+name+"/token.json", data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func decrypt(encoded []byte) (string, error) {
	keyring, err := getKeyRing()

	if err != nil {
		log.Fatal(err)
	}

	encodedReader := bytes.NewReader(encoded)
	md, err := openpgp.ReadMessage(encodedReader, keyring, pr, nil)
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

func encrypt(str string, el openpgp.EntityList) string {
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
	return base64.StdEncoding.EncodeToString(bytes)
}
