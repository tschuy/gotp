package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	otp "github.com/hgfischer/go-otp"
	"github.com/spf13/cobra"
	"github.com/tschuy/gotp/token"
)

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tkName := vars["token"]
	tk, err := token.ReadToken(tkName)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "token not found\n")
		return
	}
	totp := &otp.TOTP{Secret: tk.Token, IsBase32Secret: true}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, totp.Get())
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start an HTTP server on port 8080 sharing tokens",
	Long: `Start an HTTP server on port 8080 sharing TOTP tokens.

To get a token: curl http://localhost:8080/tokens/{name}

Intended usage: Add an auth proxy on top of the service. Two factor
tokens can then be shared between members of a team without giving the
token secret to each individual.
`,
	Run: func(cmd *cobra.Command, args []string) {
		r := mux.NewRouter()
		r.HandleFunc("/tokens/{token}", TokenHandler)
		http.Handle("/", r)

		log.Print("Starting HTTP server...")
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)
}
