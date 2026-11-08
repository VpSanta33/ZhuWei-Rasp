// Package httpx contains small HTTP helpers shared by the agent and console APIs.
package httpx

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"
)

// Envelope is the unified response: {"code":0,"message":"ok","data":...}
type Envelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func OK(w http.ResponseWriter, data any) {
	write(w, http.StatusOK, Envelope{Code: 0, Message: "ok", Data: data})
}

func Fail(w http.ResponseWriter, status int, msg string) {
	write(w, status, Envelope{Code: status, Message: msg})
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ReadJSON decodes a size-limited JSON body.
func ReadJSON(r *http.Request, limit int64, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(v)
}

func QueryInt(r *http.Request, k string, def int64) int64 {
	if v, err := strconv.ParseInt(r.URL.Query().Get(k), 10, 64); err == nil {
		return v
	}
	return def
}

func PathInt(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.PathValue(k), 10, 64)
	return v
}

// Recover turns panics into 500 responses and logs requests slower than 1s.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			if e := recover(); e != nil {
				log.Printf("panic %s %s: %v\n%s", r.Method, r.URL.Path, e, debug.Stack())
				Fail(w, http.StatusInternalServerError, "internal error")
			}
			if d := time.Since(start); d > time.Second {
				log.Printf("slow request %s %s took %s", r.Method, r.URL.Path, d)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
