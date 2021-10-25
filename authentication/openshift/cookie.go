package openshift

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// Cipher implements a custom block cipher to
// encprypt cookie values based on a given key.
type Cipher struct {
	cipher.Block
}

// NewCipher returns a new AES-based block cipher.
// On failure initializing the AES cipher for the
// given secret it returns an error.
func NewCipher(secret []byte) (*Cipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	return &Cipher{Block: c}, nil
}

// Encrypt returns the base64 encoded version of the encrypted string.
func (c *Cipher) Encrypt(value string) (string, error) {
	ciphertext := make([]byte, aes.BlockSize+len(value))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", errors.Wrap(err, "failed to create initialization vector")
	}

	stream := cipher.NewCFBEncrypter(c.Block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(value))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt returns the original encrypted string.
func (c *Cipher) Decrypt(s string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt cookie value %s")
	}

	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("encrypted cookie value should be "+
			"at least %d bytes, but is only %d bytes",
			aes.BlockSize, len(encrypted))
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(c.Block, iv)
	stream.XORKeyStream(encrypted, encrypted)

	return string(encrypted), nil
}
