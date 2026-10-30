// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
