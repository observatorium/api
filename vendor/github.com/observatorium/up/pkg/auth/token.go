package auth

import (
	"io/ioutil"
	"strings"
)

type TokenProvider interface {
	Get() (string, error)
}

func NewNoOpTokenProvider() *StaticToken {
	return &StaticToken{token: ""}
}

type StaticToken struct {
	token string
}

func NewStaticToken(token string) *StaticToken {
	return &StaticToken{token: token}
}

func (t *StaticToken) Get() (string, error) {
	return t.token, nil
}

type FileToken struct {
	file string
}

func NewFileToken(file string) *FileToken {
	return &FileToken{file: file}
}

func (t *FileToken) Get() (string, error) {
	b, err := ioutil.ReadFile(t.file)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(b)), nil
}
