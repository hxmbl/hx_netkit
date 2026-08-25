// Command correlator is the hx_netkit network intelligence CLI.
package main

import (
	"fmt"
	"os"

	"github.com/hxmbl/hx_netkit/internal/cli"
)

func main() {
	root := cli.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
