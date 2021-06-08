package transport

import (
	"io"
	"io/ioutil"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
)

func ExhaustCloseWithLogOnErr(l log.Logger, rc io.ReadCloser) {
	if _, err := io.Copy(ioutil.Discard, rc); err != nil {
		level.Warn(l).Log("msg", "failed to exhaust reader, performance may be impeded", "err", err)
	}

	if err := rc.Close(); err != nil {
		level.Warn(l).Log("msg", "detected close error", "err", errors.Wrap(err, "response body close"))
	}
}
