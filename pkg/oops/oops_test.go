package oops

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorfWraps(t *testing.T) {
	base := errors.New("boom")
	err := Errorf("dial failed: %w", base)
	if !errors.Is(err, base) {
		t.Fatalf("expected errors.Is to find wrapped error, got %v", err)
	}
	if !strings.Contains(err.Error(), "dial failed") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("unexpected message: %v", err)
	}
}

func TestInWithNew(t *testing.T) {
	err := In("Hysteria2").With("field", "Addrs").New("invalid config")
	msg := err.Error()
	if !strings.Contains(msg, "Hysteria2") || !strings.Contains(msg, "field=Addrs") || !strings.Contains(msg, "invalid config") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestTagsNew(t *testing.T) {
	err := Tags("protocol error").New("invalid address length")
	if !strings.Contains(err.Error(), "protocol error") || !strings.Contains(err.Error(), "invalid address length") {
		t.Fatalf("unexpected message: %q", err.Error())
	}
}

func TestWrapfNil(t *testing.T) {
	if err := Wrapf(nil, "x"); err != nil {
		t.Fatalf("Wrapf(nil) should return nil, got %v", err)
	}
}
