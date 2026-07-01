// Command fpcheck is a self-hostable TLS/HTTP2 fingerprint tester and differ.
package main

import (
	"os"

	"github.com/North-web-dev/fpcheck/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
