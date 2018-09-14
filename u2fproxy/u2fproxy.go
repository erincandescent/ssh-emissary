// Package u2fproxy implements a U2F device proxied over SSH agent
package u2fproxy

import (
	"github.com/flynn/u2f/u2ftoken"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type proxyDevice struct {
	agent sshagent.Agent
	key   sshagent.Key
}

var _ u2ftoken.Device = &proxyDevice{}

func NewProxyDevice(agent sshagent.Agent, key sshagent.Key) u2ftoken.Device {
	return &proxyDevice{
		agent: agent,
		key:   key,
	}
}

func (d *proxyDevice) Message(data []byte) ([]byte, error) {
	sig, err := d.agent.Sign(&d.key, data)
	if err != nil {
		return nil, err
	} else {
		return sig.Blob, nil
	}
}
