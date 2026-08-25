/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package oops is a minimal replacement for github.com/samber/oops that
// covers only the API surface outbound actually uses. It drops the heavy
// dependencies samber/oops pulled in (samber/lo, golang.org/x/text/cases and
// golang.org/x/text/language — the latter alone initializes a ~500KB BCP 47
// language registry), while keeping structured error context (domain and
// key-value attributes) for readable log messages.
package oops

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// OopsError is a minimal structured error carrying a domain, key-value
// attributes and an optional wrapped error.
type OopsError struct {
	domain  string
	message string
	attrs   []string // pre-formatted "k=v" pairs and tags
	wrapped error
}

func (e *OopsError) Error() string {
	var parts []string
	if e.domain != "" {
		parts = append(parts, e.domain)
	}
	if e.message != "" {
		parts = append(parts, e.message)
	}
	msg := strings.Join(parts, ": ")
	if len(e.attrs) > 0 {
		msg += " (" + strings.Join(e.attrs, ", ") + ")"
	}
	if e.wrapped != nil {
		msg += ": " + e.wrapped.Error()
	}
	return msg
}

func (e *OopsError) Unwrap() error { return e.wrapped }

// OopsErrorBuilder mirrors the subset of oops.OopsErrorBuilder used by
// outbound. It is a value type; mutating methods return a copy.
type OopsErrorBuilder struct {
	domain string
	attrs  []string
}

func newBuilder() OopsErrorBuilder { return OopsErrorBuilder{} }

// Errorf creates a new error with a formatted message. %w is honored: the
// referenced error is recorded as the wrapped error.
func Errorf(format string, args ...any) error {
	return newBuilder().Errorf(format, args...)
}

// Wrapf wraps an existing error with a formatted message.
func Wrapf(err error, format string, args ...any) error {
	return newBuilder().Wrapf(err, format, args...)
}

// Wrap wraps an existing error without an additional message.
func Wrap(err error) error {
	return newBuilder().Wrap(err)
}

// New creates a new error with a fixed message.
func New(message string) error {
	return newBuilder().New(message)
}

// Join combines multiple errors into one.
func Join(e ...error) error {
	return newBuilder().Join(e...)
}

// In sets the feature category or domain.
func In(domain string) OopsErrorBuilder {
	return newBuilder().In(domain)
}

// Tags adds descriptive tags.
func Tags(tags ...string) OopsErrorBuilder {
	return newBuilder().Tags(tags...)
}

func (b OopsErrorBuilder) Errorf(format string, args ...any) error {
	fe := fmt.Errorf(format, args...)
	return &OopsError{domain: b.domain, message: fe.Error(), attrs: b.attrs, wrapped: errors.Unwrap(fe)}
}

func (b OopsErrorBuilder) Wrap(err error) error {
	if err == nil {
		return nil
	}
	return &OopsError{domain: b.domain, attrs: b.attrs, wrapped: err}
}

func (b OopsErrorBuilder) Wrapf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return &OopsError{domain: b.domain, message: fmt.Sprintf(format, args...), attrs: b.attrs, wrapped: err}
}

func (b OopsErrorBuilder) New(message string) error {
	return &OopsError{domain: b.domain, message: message, attrs: b.attrs}
}

func (b OopsErrorBuilder) Join(e ...error) error {
	return b.Wrap(errors.Join(e...))
}

func (b OopsErrorBuilder) In(domain string) OopsErrorBuilder {
	b.domain = domain
	return b
}

func (b OopsErrorBuilder) Tags(tags ...string) OopsErrorBuilder {
	b.attrs = append(b.attrs, tags...)
	return b
}

// With supplies key-value attributes declared as pairs.
func (b OopsErrorBuilder) With(kv ...any) OopsErrorBuilder {
	for i := 0; i+1 < len(kv); i += 2 {
		b.attrs = append(b.attrs, fmt.Sprintf("%v=%v", kv[i], kv[i+1]))
	}
	return b
}

// WithContext attaches a context; it is not surfaced in the error message.
func (b OopsErrorBuilder) WithContext(ctx context.Context) OopsErrorBuilder {
	_ = ctx
	return b
}
