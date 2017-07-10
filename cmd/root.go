package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
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

func lengthofLongest(files []os.FileInfo) int {
	m := 0
	for _, e := range files {
		if len(e.Name()) > m {
			m = len(e.Name())
		}
	}
	return m
}

func leftPad(str string, length int) string {
	return strings.Repeat(" ", length-len(str)+1) + str
}

var RootCmd = &cobra.Command{
	Use:   "gotp",
	Short: "one-time password generation tool",
	Long:  `one-time password generation tool`,

	Run: func(cmd *cobra.Command, args []string) {
		files, _ := ioutil.ReadDir(tokenDir)
		fmt.Println(time.Now().Format(time.UnixDate))
		longest := lengthofLongest(files)
		for _, f := range files {
			mode := f.Mode()
			if mode.IsDir() {
				tk, err := token.ReadToken(f.Name())
				if err != nil {
					log.Fatalf("error reading token %s: %s", leftPad(f.Name(), longest), err)
				}
				if tk.Hotp {
					fmt.Printf("HOTP: %s\n", leftPad(tk.Name, longest))
				} else {
					totp := &otp.TOTP{Secret: tk.Token, IsBase32Secret: true}
					fmt.Printf("%s: %s\n", leftPad(tk.Name, longest), totp.Get())
				}
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
