package main

import (
	"ktbs.dev/teler/internal/runner"

	"runtime"
)

func init() {
	cpu := runtime.NumCPU()
	runtime.GOMAXPROCS(cpu + 1)
}

func main() {
	// Parse the command line flags
	options := runner.ParseOptions()
	runner.New(options)
}
