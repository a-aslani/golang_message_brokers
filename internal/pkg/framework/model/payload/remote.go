package payload

import "github.com/a-aslani/golang_message_brokers/internal/pkg/framework"

type Args struct {
	Type      string                    `json:"type"`
	Data      any                       `json:"data"`
	Publisher framework.ApplicationData `json:"publisher"`
	TraceID   string                    `json:"trace_id"`
}

type Reply struct {
	Success      bool
	ErrorMessage string
	Data         any
}
