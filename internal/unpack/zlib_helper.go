package unpack

import (
	"bytes"
	"compress/zlib"
	"io"
)

func zlibReader(b []byte) (io.ReadCloser, error) {
	return zlib.NewReader(bytes.NewReader(b))
}
