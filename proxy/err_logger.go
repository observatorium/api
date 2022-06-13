package proxy

import (
	"bytes"
	"io"
	"log"
	"os"
)

func NewErrorLogAdapter() *log.Logger {
	return log.New(&errorLogAdapter{os.Stderr}, "", log.LstdFlags)
}

type errorLogAdapter struct {
	io.Writer
}

// From https://github.com/golang/go/blob/386245b68ef4a24450a12d4f85d1835779dfef86/src/net/http/server.go#L1882
var tlsHandshakeErrStart = []byte("http: TLS handshake error from")
var tlsHandshakeErrEnd = []byte("connection reset by peer")

func (a *errorLogAdapter) Write(data []byte) (int, error) {
	// Ignore TLS handshake errors logs caused by "connection reset by peer".
	if bytes.Contains(data, tlsHandshakeErrStart) && bytes.Contains(data, tlsHandshakeErrEnd) {
		return len(data), nil
	}

	return a.Writer.Write(data)
}
