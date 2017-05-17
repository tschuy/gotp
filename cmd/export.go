package cmd

import (
	"errors"
	"fmt"
	"log"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "export a totp token",
	Long:  `export a totp token`,
	Run: func(cmd *cobra.Command, args []string) {
		tk, err := token.ReadToken(tkName)
		if err != nil {
			log.Fatal(err)
		}

		var str string
		if tk.Hotp {
			str = fmt.Sprintf("otpauth://hotp/%s?secret=%s&counter=%d", tk.Name, tk.Token, tk.Counter)
		} else {
			str = fmt.Sprintf("otpauth://totp/%s?secret=%s", tk.Name, tk.Token)
		}

		// TODO use a golang library that can do the text qr generation itself
		// qrencode is not a default nor *particularly* common
		disp := exec.Command("qrencode", str, "-t", "utf8")
		out, err := disp.Output()
		if err != nil {
			log.Fatal("Could not generate QR code. Do you have qrencode installed?")
		}

		fmt.Printf("%s", out)
		disp.Wait()
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if tkName == "" {
			return errors.New("--token name is required")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVarP(&tkName, "token", "t", "", "name of token to export")
}
