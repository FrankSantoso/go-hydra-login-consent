package log

import (
	"github.com/rs/zerolog"
	"os"
	"time"
)

// Log instantiates new zero logger
type Log struct {
	Logger *zerolog.Logger
}

// NewLogger instantiates new zerolog
func NewLogger(cmd string, pkgName string) *Log {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	z := zerolog.New(output).With().Str(cmd, pkgName).Timestamp().Logger()
	return &Log{
		Logger: &z,
	}
}
