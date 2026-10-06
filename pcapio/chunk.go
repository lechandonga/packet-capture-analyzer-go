package pcapio

import "io"

// chunkReader forces small Read sizes, used to prove parsing does not
// depend on read boundaries.
type chunkReader struct {
	r     io.Reader
	chunk int
}

// NewChunkReader wraps r so each Read returns at most chunk bytes.
func NewChunkReader(r io.Reader, chunk int) io.Reader {
	if chunk <= 0 {
		chunk = 1
	}
	return &chunkReader{r: r, chunk: chunk}
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.r.Read(p)
}
