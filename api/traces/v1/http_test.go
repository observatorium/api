package v1

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestDecompressingTransport(t *testing.T) {
	body := []byte("hello world")

	t.Run("clears Accept-Encoding and passes through uncompressed response", func(t *testing.T) {
		var capturedHeader string
		inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			capturedHeader = req.Header.Get("Accept-Encoding")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     http.Header{},
			}, nil
		})

		transport := decompressingTransport(inner)

		req, err := http.NewRequest("GET", "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "br, zstd, gzip")

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.NotEqual(t, "br, zstd, gzip", capturedHeader, "original Accept-Encoding should not be forwarded")
		assert.Empty(t, resp.Header.Get("Content-Encoding"))

		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, body, got)
	})

	t.Run("transparently decompresses gzip response", func(t *testing.T) {
		compressed := gzipBytes(t, body)
		inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(compressed)),
				Header: http.Header{
					"Content-Encoding": []string{"gzip"},
				},
			}, nil
		})

		transport := decompressingTransport(inner)

		req, err := http.NewRequest("GET", "http://localhost", nil)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, body, got)
		assert.Empty(t, resp.Header.Get("Content-Encoding"))
	})
}
