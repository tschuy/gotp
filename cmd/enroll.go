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

var tk, fps string
var fingerprints []string

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
		token.WriteToken(strSecret, tk, fingerprints)
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if tk == "" {
			return errors.New("--token name is required")
		}
		if fps == "" {
			return errors.New("--fingerprints abc123,def456 is required")
		}
		fingerprints = strings.Split(fps, ",")
		if len(fingerprints) == 0 {
			return errors.New("must encrypt with at least one key fingerprint!")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(enrollCmd)

	enrollCmd.Flags().StringVarP(&tk, "token", "t", "", "name of new token")
	enrollCmd.Flags().StringVarP(&fps, "fingerprints", "f", "", "comma-separated encryption key fingerprints")

}
