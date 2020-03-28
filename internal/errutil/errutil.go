package errutil

import "errors"

var (
	ErrNotImplemented = errors.New("Feature(s) not implemented")
	ErrMissingConsent = errors.New("Missing consent value in request")
	ErrInvalidRequest = errors.New("Incorrect request")
)
