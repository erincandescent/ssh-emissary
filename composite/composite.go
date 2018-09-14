// Package composite implements a composite agent
package composite

import (
	"bytes"
	"log"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type knownKey struct {
	fp    []byte
	agent agent.Agent
}

type CompositeAgent struct {
	agents []agent.Agent
	keys   []knownKey
}

var _ agent.Agent = &CompositeAgent{}

func New(agents []agent.Agent) *CompositeAgent {
	return &CompositeAgent{
		agents: agents,
	}
}

func (self *CompositeAgent) List() (keys []*agent.Key, err error) {
	self.keys = nil

	for _, v := range self.agents {
		kl, e := v.List()
		if e != nil {
			err = multierr.Append(err, e)
			continue
		}

		for _, k := range kl {
			self.keys = append(self.keys, knownKey{k.Blob, v})
			keys = append(keys, k)
		}
	}

	if err != nil {
		log.Printf("Encountered error listing keys: %s", err)
	}

	if len(keys) == 0 {
		return nil, err
	} else {
		return keys, nil
	}
}

func (self *CompositeAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	fp := key.Marshal()

	// Try searching for a key we know the subagent for
	for _, k := range self.keys {
		if bytes.Equal(k.fp, fp) {
			log.Print("Signing through known agent")
			s, err := k.agent.Sign(key, data)
			log.Print("Signed ", err)
			return s, err
		}
	}

	log.Print("Trying every agent")
	// Not found, just ask every agent
	for _, agent := range self.agents {
		sig, err := agent.Sign(key, data)
		if err != nil {
			continue
		}

		// Cache for the future
		self.keys = append(self.keys, knownKey{fp, agent})

		return sig, nil
	}

	return nil, errors.New("Key not found")
}

func (self *CompositeAgent) Add(key agent.AddedKey) error {
	var errs error
	for _, agent := range self.agents {
		err := agent.Add(key)
		if err != nil {
			errs = multierr.Append(errs, err)
			continue
		}
	}

	return errors.Wrap(errs, "Unable to add key (maybe none of your backends support it?)")
}

func (self *CompositeAgent) Remove(key ssh.PublicKey) (errs error) {
	fp := key.Marshal()

	ok := false
	for _, agent := range self.agents {
		if err := agent.Remove(key); err != nil {
			errs = multierr.Append(errs, err)
			continue
		}
		ok = true
	}

	keys := self.keys
	self.keys = nil
	for _, k := range keys {
		if !bytes.Equal(k.fp, fp) {
			self.keys = append(self.keys, k)
		}
	}

	if !ok {
		return errors.Wrap(errs, "Unable to remove key")
	}
	return nil

}

func (self *CompositeAgent) RemoveAll() (errs error) {
	for _, a := range self.agents {
		if err := a.RemoveAll(); err != nil {
			errs = multierr.Append(errs, err)
		}
	}
	return errs
}

func (self *CompositeAgent) Lock(passphrase []byte) (errs error) {
	for _, a := range self.agents {

		if err := a.Lock(passphrase); err != nil {
			errs = multierr.Append(errs, err)
		}
	}
	return errs
}

func (self *CompositeAgent) Unlock(passphrase []byte) (errs error) {
	for _, a := range self.agents {
		if err := a.Unlock(passphrase); err != nil {
			errs = multierr.Append(errs, err)
		}
	}
	return errs
}

func (self *CompositeAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("Not implemented")
}
