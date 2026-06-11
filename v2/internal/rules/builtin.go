package rules

import "embed"

//go:embed data/*.yaml
var builtinFS embed.FS

// Builtin loads and compiles the rules embedded in the binary.
func Builtin() ([]Rule, error) {
	return LoadFS(builtinFS, "data")
}
