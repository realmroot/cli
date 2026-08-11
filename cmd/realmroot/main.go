package main

import (
	"fmt"
	"os"

	"github.com/realmroot/toolbox/internal/cli"
)

func main() {
	if err := cli.New(os.Stdout, os.Stderr).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
