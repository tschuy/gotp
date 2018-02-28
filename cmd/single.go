package cmd

import (
	"fmt"
	"log"
	"strings"

	otp "github.com/hgfischer/go-otp"
	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
)

var singleCmd = &cobra.Command{
	Use:   "single",
	Short: "show the current value of a single TOTP token",
	Long:  `show the current value of a single TOTP token`,

	Run: func(cmd *cobra.Command, args []string) {
		tkn, err := token.ReadToken(tk)
		if err != nil {
			if strings.Contains(err.Error(), "kbx") {
				log.Fatal("It looks like you may be using a GPGv2 kbx keystore. Unfortunately gotp is only compatible with GPGv1 keystores at this time.")
			} else {
				log.Fatal(err)
			}
		}
		totp := &otp.TOTP{Secret: tkn.Token, IsBase32Secret: true}
		fmt.Printf("%s", totp.Get())
	},
}

func init() {
	singleCmd.Flags().StringVarP(&tk, "token", "t", "", "name of new token")
	singleCmd.MarkFlagRequired("token")
	RootCmd.AddCommand(singleCmd)
}
