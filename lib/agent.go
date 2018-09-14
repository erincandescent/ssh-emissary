package lib

import (
	"net"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/agent"
)

func ConnectAgent() (agent.Agent, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return nil, errors.New("SSH_AUTH_SOCK unset")
	}

	sock, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, errors.Wrap(err, "Connecting to agent")
	}

	return agent.NewClient(sock), nil
}
