package policy

import (
	"io"
	"strings"
)

func http_body(s string) io.Reader { return strings.NewReader(s) }
