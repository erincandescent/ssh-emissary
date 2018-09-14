// Package u2fagent implements a SSH Agent backend supporting U2F devices
package u2fagent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"

	"github.com/erincandescent/ssh-emissary/emissary"
	"github.com/flynn/hid"
	"github.com/flynn/u2f/u2fhid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type u2fAgent struct {
	boxSecret [32]byte
	nonceKey  [32]byte
}

var _ agent.Agent = &u2fAgent{}

func NewAgent() agent.Agent {
	agent := &u2fAgent{}
	if _, err := io.ReadFull(rand.Reader, agent.boxSecret[:]); err != nil {
		panic(err)
	}

	if _, err := io.ReadFull(rand.Reader, agent.nonceKey[:]); err != nil {
		panic(err)
	}

	return agent
}

type wireKey struct {
	Format string
	Rest   []byte `ssh:"rest"`
}

// deviceTag generates a unique secret identifier for a device
// We encrypt the path into a secretbox, using the path as
// input to HMAC to produce a constant nonce.
func (self *u2fAgent) deviceTag(dev *hid.DeviceInfo) []byte {
	var nonce [24]byte

	mac := hmac.New(sha256.New, self.nonceKey[:])
	mac.Write([]byte(dev.Path))
	sum := mac.Sum(nil)
	copy(nonce[:], sum[:24])

	return secretbox.Seal(nonce[:], []byte(dev.Path), &nonce, &self.boxSecret)
}

func (self *u2fAgent) tryOpenDeviceTag(tag []byte) string {
	if len(tag) < 24 {
		// Too short
		return ""
	}

	var nonce [24]byte
	copy(nonce[:], tag[:24])

	pathBytes, ok := secretbox.Open(nil, tag[24:], &nonce, &self.boxSecret)
	if !ok {
		return ""
	}

	mac := hmac.New(sha256.New, self.nonceKey[:])
	mac.Write(pathBytes)
	sum := mac.Sum(nil)
	if !hmac.Equal(sum[:24], nonce[:]) {
		// We should never be able to hit this case as the secretbox should
		// fail to open, but in case...
		return ""
	}

	return string(pathBytes)
}

func (self *u2fAgent) List() (keys []*agent.Key, err error) {
	devices, err := u2fhid.Devices()
	if err != nil {
		return nil, errors.Wrap(err, "Error enumerating U2F devices")
	} else {
		for i := 0; i < len(devices); i++ {
			wk := wireKey{
				Format: "u2f@e43.eu",
				Rest:   self.deviceTag(devices[i]),
			}

			keys = append(keys, &agent.Key{
				Format:  "u2f",
				Blob:    ssh.Marshal(&wk),
				Comment: devices[i].Product,
			})
		}
	}
	return
}

func (self *u2fAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if key.Type() == "u2f" {
		k := key.(*agent.Key)
		var wk wireKey

		err := ssh.Unmarshal(k.Blob, &wk)
		if err != nil {
			return nil, err
		}

		path := self.tryOpenDeviceTag(wk.Rest)
		if path == "" {
			return nil, errors.New("Device not found")
		}

		devinfo, err := hid.ByPath(path)
		if err != nil {
			return nil, err
		}
		dev, err := u2fhid.Open(devinfo)
		if err != nil {
			return nil, err
		}
		resp, err := dev.Message(data)
		if err != nil {
			return nil, err
		}

		return &ssh.Signature{
			Format: "u2f",
			Blob:   resp,
		}, nil
	}

	return nil, errors.New("Couldn't find key")
}

func (self *u2fAgent) Add(key agent.AddedKey) error {
	return errors.New("Can't add keys to U2F agent")
}

func (self *u2fAgent) Remove(key ssh.PublicKey) error {
	return errors.New("Can't remove keys from U2F agent (unplug them)")
}

func (self *u2fAgent) RemoveAll() error {
	return errors.New("Can't remove keys from U2F agent (unplug them)")
}

func (self *u2fAgent) Lock(passphrase []byte) error {
	return nil
}

func (self *u2fAgent) Unlock(passphrase []byte) error {
	return nil
}

func (self *u2fAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("Not implemented")
}

func u2fFactory(params json.RawMessage) (agent.Agent, error) {
	return NewAgent(), nil
}

func init() {
	emissary.RegisterBackend("u2f", u2fFactory)
}
