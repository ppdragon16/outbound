package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

type CipherConf2022 struct {
	KeyLen         int
	SaltLen        int
	NonceLen       int
	TagLen         int
	NewCipher      func(key []byte) (cipher.AEAD, error)
	NewBlockCipher func(key []byte) (cipher.Block, error)
}

const (
	// Timestamp tolerance
	TimestampTolerance = 30 * time.Second

	// Salt storage duration
	SaltStorageDuration = 60 * time.Second
)

var (
	Aead2022CiphersConf = map[string]*CipherConf2022{
		"2022-blake3-aes-256-gcm": {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: NewGcm, NewBlockCipher: aes.NewCipher},
		"2022-blake3-aes-128-gcm": {KeyLen: 16, SaltLen: 16, NonceLen: 12, TagLen: 16, NewCipher: NewGcm, NewBlockCipher: aes.NewCipher},
	}
)

// ValidateBase64PSK validates that the PSK is a valid base64 string with correct length
func ValidateBase64PSK(pskBase64 string, expectedKeyLen int) ([]byte, error) {
	if pskBase64 == "" {
		return nil, fmt.Errorf("PSK cannot be empty for SIP022 methods")
	}

	psk, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("PSK must be valid base64 for SIP022 methods: %w", err)
	}

	if len(psk) != expectedKeyLen {
		return nil, fmt.Errorf("PSK length must be %d bytes for this method, got %d", expectedKeyLen, len(psk))
	}

	return psk, nil
}

// SlidingWindowFilter implements a sliding window filter for packet ID replay protection
type SlidingWindowFilter struct {
	window     []uint64
	windowSize int
	latest     uint64
	mutex      sync.RWMutex
}

// NewSlidingWindowFilter creates a new sliding window filter
func NewSlidingWindowFilter(windowSize int) *SlidingWindowFilter {
	return &SlidingWindowFilter{
		window:     make([]uint64, windowSize),
		windowSize: windowSize,
	}
}

// CheckAndUpdate checks if the packet ID is valid and updates the window
func (f *SlidingWindowFilter) CheckAndUpdate(packetID uint64) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Packet ID too old
	if packetID+uint64(f.windowSize) <= f.latest {
		return false
	}

	// Packet ID in the future, update latest
	if packetID > f.latest {
		// Shift window
		shift := packetID - f.latest
		if shift >= uint64(f.windowSize) {
			// Clear entire window
			for i := range f.window {
				f.window[i] = 0
			}
		} else {
			// Shift window by 'shift' positions
			for i := 0; i < len(f.window)-int(shift); i++ {
				f.window[i] = f.window[i+int(shift)]
			}
			for i := len(f.window) - int(shift); i < len(f.window); i++ {
				f.window[i] = 0
			}
		}
		f.latest = packetID
		return true
	}

	// Packet ID in the window
	index := int(f.latest - packetID)
	if index >= f.windowSize {
		return false
	}

	wordIndex := index / 64
	bitIndex := index % 64
	mask := uint64(1) << bitIndex

	// Check if already seen
	if f.window[wordIndex]&mask != 0 {
		return false
	}

	// Mark as seen
	f.window[wordIndex] |= mask
	return true
}
