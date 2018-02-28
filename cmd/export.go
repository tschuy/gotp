package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"

	"github.com/qpliu/qrencode-go/qrencode"
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

		grid, err := qrencode.Encode(str, qrencode.ECLevelL)
		if err != nil {
			panic(err)
		}
		grid.TerminalOutput(os.Stdout)
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVarP(&tkName, "token", "t", "", "name of token to export")
	exportCmd.MarkFlagRequired("token")
}
