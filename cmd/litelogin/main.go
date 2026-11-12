// Command litelogin manages a LiteLogin deployment through its Admin API.
// See internal/cli and Architecture.md ("CLI").
package main

import (
	"os"

	"github.com/litelogin/litelogin/internal/cli"
)

func main() {
	os.Exit(cli.Execute(cli.NewApp(), os.Args[1:]))
}
