package mw

import (
	"github.com/FrankSantoso/go-hydra-login-consent/internal/log"
	"github.com/go-chi/chi/middleware"
	"net/http"
	"runtime/debug"
	"time"
)

func ReqLoggerMw(l *log.Log) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			t1 := time.Now()
			defer func() {
				t2 := time.Now()

				// Recover and record stack traces in case of a panic
				if rec := recover(); rec != nil {
					l.Logger.Error().
						Str("type", "error").
						Timestamp().
						Interface("recover_info", rec).
						Bytes("debug_stack", debug.Stack()).
						Msg("log system error")
					http.Error(ww, http.StatusText(http.StatusInternalServerError),
						http.StatusInternalServerError)
				}

				l.Logger.Log().
					Timestamp().
					Int("Status:", ww.Status()).
					Str("Method: ", r.Method).
					Str("Path: ", r.URL.Path).
					Str("-> ", r.RemoteAddr).
					Str("UA", r.Header.Get("User-Agent")).
					Dur("Latency: ", t2.Sub(t1)).
					Msg("")
			}()
			next.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}
}
