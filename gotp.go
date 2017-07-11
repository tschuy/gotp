package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/tschuy/gotp/cmd"
)

var systemdSocket = "/run/user/" + strconv.FormatInt(int64(os.Getuid()), 10) + "/gnupg/S.gpg-agent"
var homeSocket = os.Getenv("HOME") + "/.gnupg/S.gpg-agent"

// how can we connect to GPG Agent? there are a few ways:
//   * gpg-agent before v2: stored in GPG_AGENT_INFO
//   * gpg-agent after v2: stored in "a stable pathname now", according to the Debian docs
//		* on systemd, this means /run/user/[uid]/gnupg/S.gpg-agent
//		* in general, $HOME/.gnupg/S.gpg-agent
// https://wiki.debian.org/Teams/GnuPG/UsingGnuPGv2#GPG_AGENT_INFO_variable
func setupSocket() error {
	if os.Getenv("GPG_AGENT_INFO") != "" {
		return nil
	}
	if _, err := os.Stat(systemdSocket); !os.IsNotExist(err) {
		os.Setenv("GPG_AGENT_INFO", systemdSocket+":12345:1")
		return nil
	}
	if _, err := os.Stat(homeSocket); !os.IsNotExist(err) {
		os.Setenv("GPG_AGENT_INFO", homeSocket+":12345:1")
		return nil
	}

	return errors.New("unable to find gpg-agent")
}

func main() {
	err := setupSocket()
	if err != nil {
		fmt.Println("Could not find gpg-agent; is it running?")
		os.Exit(1)
	}

	cmd.Execute()
}
