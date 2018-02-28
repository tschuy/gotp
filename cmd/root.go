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
	"github.com/spf13/viper"
	"github.com/tschuy/gotp/token"
)

func lengthofLongest(files []os.FileInfo) int {
	m := 0
	for _, e := range files {
		if len(e.Name()) > m {
			m = len(e.Name())
		}
	}
	return m
}

var RootCmd = &cobra.Command{
	Use:   "gotp",
	Short: "one-time password generation tool",
	Long:  `one-time password generation tool`,

	Run: func(cmd *cobra.Command, args []string) {
		files, _ := ioutil.ReadDir(viper.GetString("token-directory"))
		fmt.Println(time.Now().Format(time.UnixDate))
		longest := lengthofLongest(files)
		for _, f := range files {
			mode := f.Mode()
			if mode.IsDir() {
				tk, err := token.ReadToken(f.Name())
				if err != nil {
					if strings.Contains(err.Error(), "kbx") {
						log.Fatal("It looks like you may be using a GPGv2 kbx keystore. Unfortunately gotp is only compatible with GPGv1 keystores at this time.")
					}
					log.Fatalf("error reading token %*s: %s", longest, f.Name(), err)
				}
				if tk.Hotp {
					fmt.Printf(" %*s: %s\n", longest, tk.Name, "HOTP")
				} else {
					totp := &otp.TOTP{Secret: tk.Token, IsBase32Secret: true}
					fmt.Printf(" %*s: %s\n", longest, tk.Name, totp.Get())
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

func init() {
	RootCmd.PersistentFlags().StringP("token-directory", "d", "~/.otptokens", "the directory where tokens are stored")

	viper.SetDefault("token-directory", os.Getenv("HOME")+"/.otptokens")
	viper.BindPFlag("token-directory", RootCmd.PersistentFlags().Lookup("token-directory"))
}
