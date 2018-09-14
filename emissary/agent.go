// Package emissary implements a composite agent
package emissary

import (
	"encoding/json"
	"net"

	"github.com/erincandescent/ssh-emissary/composite"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/agent"
	tilde "gopkg.in/mattes/go-expand-tilde.v1"
)

func Create(data []byte) (agent.Agent, error) {
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	var backends []agent.Agent
	for _, v := range config.Backends {
		a, err := CreateBackend(v.Type, v.Params)
		if err != nil {
			return nil, errors.Wrapf(err, "Creating %s backend", v.Type)
		}
		backends = append(backends, a)
	}

	return composite.New(backends), nil
}

type AgentFactory func(params json.RawMessage) (agent.Agent, error)

type proxyConfig struct {
	Socket string `json:"socket"`
}

func proxyFactory(params json.RawMessage) (agent.Agent, error) {
	var config proxyConfig
	if err := json.Unmarshal(params, &config); err != nil {
		return nil, err
	}

	sock, err := tilde.Expand(config.Socket)
	if err != nil {
		return nil, err
	}

	s, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}

	return agent.NewClient(s), nil
}

var factories map[string]AgentFactory = map[string]AgentFactory{
	"proxy": proxyFactory,
}

func CreateBackend(name string, params json.RawMessage) (agent.Agent, error) {
	if f, ok := factories[name]; ok {
		return f(params)
	}
	return nil, errors.Errorf("Unknown type %s", name)
}

func RegisterBackend(name string, factory AgentFactory) {
	factories[name] = factory
}
