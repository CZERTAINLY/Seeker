package model

import (
	"errors"
)

var (
	ErrTooBig  = errors.New("file too big")
	ErrNoMatch = errors.New("no match")
)
