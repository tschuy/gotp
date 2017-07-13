package cmd

import (
	"errors"
	"fmt"
	"log"

	"strings"

	"os"

	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
)

var f bool

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete a token",
	Long:  `delete a token`,
	Run: func(cmd *cobra.Command, args []string) {
		if !f {
			var ans string
			fmt.Printf("Are you sure you want to remove token %s? y/[N] ", tk)
			_, err := fmt.Scanln(&ans)
			if err != nil {
				log.Fatal(err)
			}
			if !(strings.HasPrefix(ans, "y") || strings.HasPrefix(ans, "Y")) {
				fmt.Println("cancelling operation!")
				return
			}
		}
		fmt.Printf("Deleting token %s...\n", tk)
		err := token.DeleteToken(tk)
		if err != nil && os.IsNotExist(err) {
			fmt.Printf("Could not find token %s\n", tk)
			os.Exit(1)
		} else if err != nil {
			fmt.Print("Could not delete token: ")
			log.Fatal(err)
		} else {
			fmt.Println("Token deleted successfully!")
		}
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if tk == "" {
			return errors.New("--token name is required")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(deleteCmd)

	deleteCmd.Flags().StringVarP(&tk, "token", "t", "", "name of token")
	deleteCmd.Flags().BoolVarP(&f, "force", "f", false, "force removal (do not prompt)")
}
