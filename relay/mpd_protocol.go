package relay

import (
	"fmt"
	"io"
)

// MPDResponse provides a structured way to build MPD protocol responses
type MPDResponse struct {
	w io.Writer
}

// NewMPDResponse creates a new MPDResponse builder
func NewMPDResponse(w io.Writer) *MPDResponse {
	return &MPDResponse{w: w}
}

// Field writes a key-value pair to the response
func (r *MPDResponse) Field(key string, value interface{}) {
	fmt.Fprintf(r.w, "%s: %v\n", key, value)
}

// OK writes the standard success terminator
func (r *MPDResponse) OK() {
	fmt.Fprint(r.w, "OK\n")
}

// ListOK writes the success terminator for a command list item
func (r *MPDResponse) ListOK() {
	fmt.Fprint(r.w, "list_OK\n")
}

// ACK writes a protocol error in the format: ACK [error_code@list_pos] {command} message
func (r *MPDResponse) ACK(errorCode, listPos int, command, message string) {
	fmt.Fprintf(r.w, "ACK [%d@%d] {%s} %s\n", errorCode, listPos, command, message)
}

// Greeting writes the initial MPD version string
func (r *MPDResponse) Greeting(version string) {
	fmt.Fprintf(r.w, "OK MPD %s\n", version)
}

// Binary writes binary data in MPD format
func (r *MPDResponse) Binary(data []byte) {
	fmt.Fprintf(r.w, "binary: %d\n", len(data))
	r.w.Write(data)
	fmt.Fprint(r.w, "\n")
}
