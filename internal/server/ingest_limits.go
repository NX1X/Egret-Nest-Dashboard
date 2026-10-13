package server

import (
	"bytes"
	"encoding/json"
	"errors"
)

// maxIngestElements caps the total number of array elements in one envelope,
// counted across every array in the document. The 8 MiB byte cap does not bound
// memory on its own: 8 MiB of `{}` is about 2.8 million elements, and each one
// decodes into a full struct. 8 MiB of real Egret entries is under about 60,000
// elements, so this cap rejects only crafted payloads.
const maxIngestElements = 100_000

// maxIngestDepth caps JSON nesting. A real envelope nests about 5 levels. Without
// a cap, an 8 MiB run of '[' would grow the tokenizer stacks to millions of
// entries.
const maxIngestDepth = 32

var (
	errIngestTooLarge  = errors.New("payload has too many entries or is nested too deeply")
	errIngestMalformed = errors.New("invalid JSON payload")
)

// checkIngestShape walks the tokens of the first top-level JSON value without
// building Go values, and rejects a payload whose decode would cost far more
// memory than its size suggests. Its own memory use is bounded by
// maxIngestDepth. Data after the first top-level value is ignored, the same as
// json.Decoder.Decode.
func checkIngestShape(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []json.Delim
	elements := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return errIngestMalformed
		}
		d, isDelim := tok.(json.Delim)
		if isDelim && (d == ']' || d == '}') {
			if len(stack) == 0 {
				return errIngestMalformed
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return nil // end of the top-level value
			}
			continue
		}
		// Any value (scalar, object or array) that starts directly inside an
		// array is one element of that array.
		if len(stack) > 0 && stack[len(stack)-1] == '[' {
			elements++
			if elements > maxIngestElements {
				return errIngestTooLarge
			}
		}
		if isDelim {
			if len(stack) == maxIngestDepth {
				return errIngestTooLarge
			}
			stack = append(stack, d)
			continue
		}
		if len(stack) == 0 {
			return nil // a top-level scalar; the typed decode rejects it
		}
	}
}
