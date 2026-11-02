package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

const (
	magic     = "PPS1"
	saltBytes = 16
	chunkSize = 1 << 20
)

// Keys holds subkeys derived from the master key. Object names use their own
// subkey so that a bucket listing cannot confirm whether a known file is stored.
type Keys struct{ enc, id []byte }

func deriveKeys(master []byte) (Keys, error) {
	if len(master) != 32 {
		return Keys{}, errors.New("key must be exactly 32 bytes")
	}
	enc, err := hkdf.Key(sha256.New, master, nil, "pinpin-store/encrypt/v1", 32)
	if err != nil {
		return Keys{}, err
	}
	id, err := hkdf.Key(sha256.New, master, nil, "pinpin-store/name/v1", 32)
	if err != nil {
		return Keys{}, err
	}
	return Keys{enc: enc, id: id}, nil
}

func loadKeys(path string) (Keys, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Keys{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Keys{}, fmt.Errorf("key file %s must not be group or world accessible", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Keys{}, err
	}
	return deriveKeys(raw)
}

func (k Keys) objectID(sha string) string {
	m := hmac.New(sha256.New, k.id)
	m.Write([]byte(sha))
	return hex.EncodeToString(m.Sum(nil))
}

func (k Keys) aead(salt []byte, id string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, k.enc, salt, "object:"+id, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nonce(counter uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], counter)
	if last {
		n[11] = 1
	}
	return n
}

// encrypt streams r into w as fixed-size AEAD chunks. The final chunk carries a
// flag in its nonce, so truncating the object at a chunk boundary fails to open.
func (k Keys) encrypt(w io.Writer, r io.Reader, id string) (sha string, size int64, err error) {
	salt := make([]byte, saltBytes)
	if _, err = rand.Read(salt); err != nil {
		return "", 0, err
	}
	aead, err := k.aead(salt, id)
	if err != nil {
		return "", 0, err
	}
	if _, err = w.Write(append([]byte(magic), salt...)); err != nil {
		return "", 0, err
	}
	sum := sha256.New()
	in := bufio.NewReaderSize(r, chunkSize)
	plain := make([]byte, chunkSize)
	sealed := make([]byte, 0, chunkSize+aead.Overhead())
	for counter := uint64(0); ; counter++ {
		n, readErr := io.ReadFull(in, plain)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return "", 0, readErr
		}
		last := readErr != nil
		if !last {
			if _, peekErr := in.Peek(1); peekErr == io.EOF {
				last = true
			} else if peekErr != nil {
				return "", 0, peekErr
			}
		}
		sum.Write(plain[:n])
		size += int64(n)
		if _, err = w.Write(aead.Seal(sealed[:0], nonce(counter, last), plain[:n], []byte(id))); err != nil {
			return "", 0, err
		}
		if last {
			return hex.EncodeToString(sum.Sum(nil)), size, nil
		}
	}
}

func (k Keys) decrypt(w io.Writer, r io.Reader, id string) (sha string, size int64, err error) {
	head := make([]byte, len(magic)+saltBytes)
	if _, err = io.ReadFull(r, head); err != nil {
		return "", 0, fmt.Errorf("object header: %w", err)
	}
	if string(head[:len(magic)]) != magic {
		return "", 0, errors.New("not a pinpin-store object")
	}
	aead, err := k.aead(head[len(magic):], id)
	if err != nil {
		return "", 0, err
	}
	in := bufio.NewReaderSize(r, chunkSize+aead.Overhead())
	sealed := make([]byte, chunkSize+aead.Overhead())
	var sum hash.Hash = sha256.New()
	for counter := uint64(0); ; counter++ {
		n, readErr := io.ReadFull(in, sealed)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return "", 0, fmt.Errorf("object body: %w", readErr)
		}
		last := readErr != nil
		if !last {
			if _, peekErr := in.Peek(1); peekErr == io.EOF {
				last = true
			} else if peekErr != nil {
				return "", 0, peekErr
			}
		}
		plain, openErr := aead.Open(nil, nonce(counter, last), sealed[:n], []byte(id))
		if openErr != nil {
			return "", 0, errors.New("object failed authentication: corrupt, truncated, or wrong key")
		}
		sum.Write(plain)
		size += int64(len(plain))
		if _, err = w.Write(plain); err != nil {
			return "", 0, err
		}
		if last {
			return hex.EncodeToString(sum.Sum(nil)), size, nil
		}
	}
}
