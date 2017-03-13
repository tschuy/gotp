package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"

	"github.com/hgfischer/go-otp"

	"golang.org/x/crypto/openpgp"
)

// ability to encrypt a file with one gpg key                 [:+1:]
// ability to encrypt a file with MULTIPLE gpg keys           [:+1:]
// ability to reference keys by id, not by including here     []
// cli to add a token (and have it automatically encrypted)   []
// nice listing of all added tokens                           []
// generate an OTP token from a TOTP token                    []

const prefix, passphrase = "/home/tschuy/", "password"
const secretKeyring = prefix + ".gnupg/secring.gpg"
const publicKeyring = prefix + ".gnupg/pubring.gpg"

func getKeyRing() (*openpgp.EntityList, error) {
	log.Println("Reading gpg keyring from:", secretKeyring)

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

func main() {
	// myStr := "ZVB267QPFBAGROTDE6US5UN255A5BJAOKAJY2VMU3EZWNYCGKBLIVLJ3QB6N6GWR"
	// encrypt(myStr) // saves myStr to test.gpg
	log.Println("Reading token from:", "test.gpg")
	res, err := decrypt()

	if err != nil {
		log.Fatal(err)
	}

	log.Print("secret otp key: ", res)

	totp := &otp.TOTP{Secret: res, IsBase32Secret: true}
	log.Print(totp.Get())
}

func pr(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	passphraseByte := []byte(passphrase)

	for i := range keys {
		keys[i].PrivateKey.Decrypt(passphraseByte)
	}
	return nil, nil
}

func decrypt() (string, error) {

	keyring, err := getKeyRing()

	if err != nil {
		log.Fatal(err)
	}

	f, _ := os.Open("test.gpg")
	md, err := openpgp.ReadMessage(f, keyring, pr, nil)
	if err != nil {
		return "", nil
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil

}

func encrypt(str string) {
	el1, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(tschuyKey))
	if err != nil {
		log.Fatal(err)
	}

	// el2, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(rbKey))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// el3, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(testPub))
	// if err != nil {
	// 	log.Fatal(err)
	// }

	entitylist := el1
	// entitylist := append(el1, el2[0])
	// entitylist = append(entitylist, el3[0])

	// Encrypt message using public key
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entitylist, nil, nil, nil)
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

const token = "ZVB267QPFBAGROTDE6US5UN255A5BJAOKAJY2VMU3EZWNYCGKBLIVLJ3QB6N6GWR"

const testPriv = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

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
/4BOnRHT
=4JaG
-----END PGP PRIVATE KEY BLOCK-----`

const testPub = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

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
OudpP5we3ktgZ0qdNhb/gE6dEdM=
=I3UE
-----END PGP PUBLIC KEY BLOCK-----`
