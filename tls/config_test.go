package tls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/observatorium/api/logger"
)

func TestMapCurveNamesToIDs(t *testing.T) {
	tests := []struct {
		name       string
		input      []string
		want       []tls.CurveID
		errContain string
	}{
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
		{
			name: "all supported names (IANA and Go constant)",
			input: []string{
				// X25519 and the ML-KEM hybrids: IANA name == Go constant name.
				"X25519",
				"X25519MLKEM768",
				"SecP256r1MLKEM768",
				"SecP384r1MLKEM1024",
				// Classic EC curves: IANA name and Go constant name.
				"secp256r1", "CurveP256",
				"secp384r1", "CurveP384",
				"secp521r1", "CurveP521",
			},
			want: []tls.CurveID{
				tls.X25519,
				tls.X25519MLKEM768,
				tls.SecP256r1MLKEM768,
				tls.SecP384r1MLKEM1024,
				tls.CurveP256, tls.CurveP256,
				tls.CurveP384, tls.CurveP384,
				tls.CurveP521, tls.CurveP521,
			},
		},
		{
			name:  "mixed IANA and Go constant names",
			input: []string{"secp256r1", "CurveP384"},
			want:  []tls.CurveID{tls.CurveP256, tls.CurveP384},
		},
		{
			name:       "unknown curve name",
			input:      []string{"CurveUnknown"},
			errContain: "unknown TLSCurve: CurveUnknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapCurveNamesToIDs(tc.input)
			if tc.errContain != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.errContain)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNewServerConfigCurvePreferences(t *testing.T) {
	certPath, keyPath, cleanCerts, err := newSelfSignedCert("localhost")
	require.NoError(t, err)
	defer cleanCerts()

	l := logger.NewLogger("info", logger.LogFormatLogfmt, "")

	tests := []struct {
		name        string
		curves      []string
		want        []tls.CurveID
		errContains []string
	}{
		{
			name:   "omitted uses default curves",
			curves: nil,
			want:   nil,
		},
		{
			name: "configured curve preferences",
			curves: []string{
				"X25519MLKEM768",
				"X25519",
				"secp256r1",
				"CurveP384",
				"secp521r1",
				"SecP256r1MLKEM768",
				"SecP384r1MLKEM1024",
			},
			want: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				tls.SecP256r1MLKEM768,
				tls.SecP384r1MLKEM1024,
			},
		},
		{
			name:   "invalid curve preferences",
			curves: []string{"CurveUnknown"},
			errContains: []string{
				"TLS curve preference name to ID conversion",
				"unknown TLSCurve: CurveUnknown",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewServerConfig(
				l,
				certPath,
				keyPath,
				"VersionTLS13",
				"VersionTLS13",
				"RequestClientCert",
				nil,
				tc.curves,
			)
			if len(tc.errContains) > 0 {
				require.Error(t, err)
				for _, msg := range tc.errContains {
					require.ErrorContains(t, err, msg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, cfg.CurvePreferences)
		})
	}
}
