package prefix 

import (
	"encoding/binary"
	"io"
)

func WritePrefix(w io.Writer, p []byte) (n int, err error) {
	length := len(p)
	buf := make([]byte, 2)
	buf = append(buf, p...)
	binary.LittleEndian.PutUint16(buf[:2], uint16(length))
	return w.Write(buf)
}

func ReadPrefix(r io.Reader) ([]byte, error) {
	lenbuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenbuf); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint16(lenbuf)
	buf := make([]byte, length)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

