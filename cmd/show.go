package cmd

import (
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"

	otp "github.com/hgfischer/go-otp"
	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
	"golang.org/x/crypto/ssh/terminal"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "show the current value of a temporary TOTP token",
	Long:  `show the current value of a temporary TOTP token`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Paste secret: ")
		byteSecret, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal(err)
		}
		strSecret := string(byteSecret)
		strSecret = strings.ToUpper(strSecret)
		err = token.Verify(strSecret)
		if err != nil {
			log.Fatal(err)
		}
		totp := &otp.TOTP{Secret: strSecret, IsBase32Secret: true}
		fmt.Println(time.Now().Format(time.UnixDate))
		fmt.Printf("Token: %s\n", totp.Get())
	},
}

func init() {
	RootCmd.AddCommand(showCmd)
}
