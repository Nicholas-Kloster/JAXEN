// murmur3.go — inline MurmurHash3 32-bit implementation
//
// Used by cmdPivot to compute Shodan's favicon hash.
// Shodan's algorithm: MurmurHash3(base64_encodebytes(favicon_bytes))
// where base64_encodebytes inserts a '\n' every 76 base64 chars (Python behavior).
package main

import (
	"bytes"
	"encoding/base64"
)

// murmur3Hash32 computes the MurmurHash3 32-bit hash of data with seed 0.
// Returns a signed int32 to match Shodan's hash representation.
func murmur3Hash32(data []byte) int32 {
	const (
		c1 = uint32(0xcc9e2d51)
		c2 = uint32(0x1b873593)
	)

	h1 := uint32(0) // seed = 0
	length := len(data)
	nblocks := length / 4

	// ── Body: process 4-byte blocks ──────────────────────────────────────
	for i := 0; i < nblocks; i++ {
		off := i * 4
		k1 := uint32(data[off]) | uint32(data[off+1])<<8 |
			uint32(data[off+2])<<16 | uint32(data[off+3])<<24

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17) // rotl32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19) // rotl32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	// ── Tail: remaining 1–3 bytes ─────────────────────────────────────────
	tail := data[nblocks*4:]
	var k1 uint32
	switch length & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// ── Finalization (fmix32) ─────────────────────────────────────────────
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}

// shodanFaviconBase64 encodes raw favicon bytes exactly as Python's
// base64.encodebytes() does: standard base64 with a '\n' appended after
// every 76 characters AND at the very end of the output.
// This is the pre-hash encoding step in Shodan's favicon fingerprint.
func shodanFaviconBase64(raw []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(raw)
	var buf bytes.Buffer
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
