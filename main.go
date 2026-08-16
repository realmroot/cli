package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/realmroot/cli/internal/cli"
)

func main() {
	if err := cli.New(os.Stdout, os.Stderr).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var exited interface{ ExitCode() int }
		if errors.As(err, &exited) {
			os.Exit(exited.ExitCode())
		}
		os.Exit(1)
	}
}
