package local

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadCertFile: a hostile or corrupt file under cert_paths must
// give records or an error, never a panic.
func FuzzReadCertFile(f *testing.F) {
	der := []byte{0x30, 0x82, 0x01, 0x00, 0x30}
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), ".pem")
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ".crt")
	f.Add(der, ".der")
	f.Add([]byte{}, ".cer")
	f.Fuzz(func(t *testing.T, data []byte, ext string) {
		switch ext {
		case ".pem", ".crt", ".cer", ".der":
		default:
			ext = ".pem"
		}
		p := filepath.Join(t.TempDir(), "x"+ext)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		certs, err := readCertFile(p)
		if err == nil {
			_ = records("file://"+p, certs)
		}
	})
}
