package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/hgfischer/go-otp"
	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
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

var RootCmd = &cobra.Command{
	Use:   "gotp",
	Short: "one-time password generation tool",
	Long:  `one-time password generation tool`,

	Run: func(cmd *cobra.Command, args []string) {
		files, _ := ioutil.ReadDir(tokenDir)
		fmt.Println(time.Now().Format(time.UnixDate))
		for _, f := range files {
			mode := f.Mode()
			if mode.IsDir() {
				tk, err := token.ReadToken(f.Name())
				if err != nil {
					log.Fatalf("error reading token %s: %s", f.Name(), err)
				}
				decrypted, err := token.Decrypt(tk.EncryptedToken)
				if err != nil {
					log.Fatal(err)
				}
				totp := &otp.TOTP{Secret: string(decrypted), IsBase32Secret: true}
				fmt.Printf("%s: %s\n", tk.Name, totp.Get())
			}
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
