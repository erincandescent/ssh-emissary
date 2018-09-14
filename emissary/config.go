package emissary

import "encoding/json"

type Config struct {
	Backends []Backend `json:"backends"`
}

type Backend struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params"`
}
