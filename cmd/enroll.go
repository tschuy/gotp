package cmd

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
	"golang.org/x/crypto/ssh/terminal"
)

var tk, fps, ems string
var fingerprints []string
var emails []string
var counter uint64
var hotp bool

// enrollCmd represents the enroll command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "enroll a new token",
	Long:  `enroll a new token`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Paste secret: ")
		byteSecret, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal(err)
		}
		strSecret := string(byteSecret)
		err = token.Verify(strSecret)
		if err != nil {
			log.Fatal(err)
		}
		err = token.WriteToken(strSecret, tk, fingerprints, emails, hotp, counter)
		if err != nil {
			log.Fatal(err)
		}
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if tk == "" {
			return errors.New("--token name is required")
		}
		if fps != "" {
			fingerprints = strings.Split(fps, ",")
		}

		if ems != "" {
			emails = strings.Split(ems, ",")
		}

		if len(fingerprints) == 0 && len(emails) == 0 {
			return errors.New("must encrypt with at least one key (fingerprint or email)!")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(enrollCmd)

	enrollCmd.Flags().StringVarP(&tk, "token", "t", "", "name of new token")
	enrollCmd.Flags().StringVarP(&fps, "fingerprints", "f", "", "comma-separated encryption key fingerprints")
	enrollCmd.Flags().StringVarP(&ems, "emails", "e", "", "comma-separated emails for encryption")
	enrollCmd.Flags().Uint64VarP(&counter, "counter", "c", 0, "hotp count")
	enrollCmd.Flags().BoolVarP(&hotp, "hotp", "", false, "enroll hotp token")
}
