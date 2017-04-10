package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
)

var tk, fps string
var fingerprints []string

// enrollCmd represents the enroll command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "enroll a new token",
	Long:  `enroll a new token`,
	Run: func(cmd *cobra.Command, args []string) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter text: ")
		text, _ := reader.ReadString('\n')
		token.WriteToken(text, tk, fingerprints)
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
