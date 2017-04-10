package main

import (
	"os"
	"strconv"

	"github.com/tschuy/gotp/cmd"
)

func main() {
	// horrible hack
	os.Setenv("GPG_AGENT_INFO",
		"/run/user/"+strconv.FormatInt(int64(os.Getuid()), 10)+"/gnupg/S.gpg-agent:12345:1")
	cmd.Execute()
}
