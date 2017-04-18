package cmd

import (
	"errors"
	"fmt"
	"log"

	"github.com/hgfischer/go-otp"
	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
)

var tkName string

var incrementCmd = &cobra.Command{
	Use:   "increment",
	Short: "increment an hotp token",
	Long:  `increment an hotp token`,
	Run: func(cmd *cobra.Command, args []string) {
		tk, err := token.ReadToken(tkName)
		if err != nil {
			log.Fatal(err)
		}

		if tk.Hotp {
			hotp := &otp.HOTP{Secret: tk.Token, Counter: tk.Counter, IsBase32Secret: true}
			fmt.Printf("incrementing from %s: %s\n", tk.Name, hotp.Get())
			err = token.WriteToken(tk.Token, tk.Name, tk.StrFingerprints, nil, true, tk.Counter+1)
			if err != nil {
				log.Fatal(err)
			}
			return
		} else {
			fmt.Printf("token %s is not an HOTP token!", tkName)
			return
		}

	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if tkName == "" {
			return errors.New("--token name is required")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(incrementCmd)
	incrementCmd.Flags().StringVarP(&tkName, "token", "t", "", "name of token to increment")
}
