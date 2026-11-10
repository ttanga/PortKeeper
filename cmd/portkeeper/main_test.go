package main

import (
	"errors"
	"strings"
	"testing"
)

func TestReadPasswordFromLine(t *testing.T) {
	got, err := readPasswordFrom(strings.NewReader("correct horse battery staple\n"))
	if err != nil {
		t.Fatalf("readPasswordFrom returned error: %v", err)
	}
	if got != "correct horse battery staple" {
		t.Fatalf("got %q, want password without newline", got)
	}
}

func TestReadPasswordFromAcceptsEOFWithoutNewline(t *testing.T) {
	got, err := readPasswordFrom(strings.NewReader("password-at-eof"))
	if err != nil {
		t.Fatalf("readPasswordFrom returned error: %v", err)
	}
	if got != "password-at-eof" {
		t.Fatalf("got %q, want %q", got, "password-at-eof")
	}
}

func TestReadPasswordFromRejectsEmptyPassword(t *testing.T) {
	_, err := readPasswordFrom(strings.NewReader("\n"))
	if err == nil {
		t.Fatal("expected empty password to be rejected")
	}
}

func TestReadPasswordFromPropagatesReadError(t *testing.T) {
	wantErr := errors.New("input failed")
	reader := errorReader{err: wantErr}
	_, err := readPasswordFrom(reader)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
