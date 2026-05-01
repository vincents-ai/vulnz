package main

import (
	"fmt"
	"os"

	"github.com/vincents-ai/vulnz/internal/cli"
	_ "github.com/vincents-ai/vulnz/internal/providers"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
