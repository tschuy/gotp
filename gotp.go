package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/tschuy/gotp/cmd"
)

func main() {
	if _, err := os.Stat("/run/user/" + strconv.FormatInt(int64(os.Getuid()), 10) + "/gnupg/S.gpg-agent"); os.IsNotExist(err) && os.Getenv("GPG_AGENT_INFO") == "" {
		fmt.Print("Unable to find gpg-agent; is it running?\n")
		os.Exit(1)
	}

	// how can we connect to GPG Agent? there are a few ways:
	//   * gpg-agent before v2: stored in GPG_AGENT_INFO
	//   * gpg-agent after v2: stored in "a stable pathname now", according to the Debian docs
	//		* on systemd, this means /run/user/[uid]/gnupg/S.gpg-agent
	//		* on other init systems that don't use FHS, let alone other OSes, more research is necessary
	// https://wiki.debian.org/Teams/GnuPG/UsingGnuPGv2#GPG_AGENT_INFO_variable
	if os.Getenv("GPG_AGENT_INFO") == "" {
		os.Setenv("GPG_AGENT_INFO",
			"/run/user/"+strconv.FormatInt(int64(os.Getuid()), 10)+"/gnupg/S.gpg-agent:12345:1")
	}
	cmd.Execute()
}
