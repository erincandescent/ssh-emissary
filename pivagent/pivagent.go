// package pivagent implements a SSH agent backed by a PIV smartcard
package pivagent

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"

	"github.com/erincandescent/cardkit/piv"
	"github.com/erincandescent/cardkit/protocol"
	"github.com/erincandescent/ssh-emissary/emissary"
	"github.com/foxcpp/go-assuan/pinentry"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type knownKey struct {
	fp  []byte
	id  piv.KeyID
	pub crypto.PublicKey
}

type pivAgent struct {
	card      *protocol.Card
	knownKeys []knownKey
}

var _ agent.Agent = &pivAgent{}

func NewAgent(card *protocol.Card) agent.Agent {
	agent := &pivAgent{card: card}
	return agent
}

func (self *pivAgent) List() (keys []*agent.Key, err error) {
	self.knownKeys = nil
	if err := self.card.Lock(); err != nil {
		return nil, errors.Wrap(err, "Error locking card")
	}
	defer self.card.Unlock()

	if err := piv.SelectApp(self.card); err != nil {
		return nil, errors.Wrap(err, "Error selecting PIV app")
	}

	keyIds := []piv.KeyID{piv.AuthenticationKey, piv.CardAuthenticationKey}

	for _, id := range keyIds {
		cert, err := piv.GetCertificate(self.card, id)
		if err != nil {
			log.Printf("Error getting %s key: %s", id.GetInfo().Name, err)
			continue
		}

		x509cert, err := cert.ParseX509Certificate()
		if err != nil {
			log.Printf("Error parsing %s key: %s", id.GetInfo().Name, err)
			continue
		}

		sshkey, err := ssh.NewPublicKey(x509cert.PublicKey)
		if err != nil {
			log.Printf("Error converting to ssh key: %s", err)
			continue
		}

		self.knownKeys = append(self.knownKeys, knownKey{sshkey.Marshal(), id, x509cert.PublicKey})

		keys = append(keys, &agent.Key{
			Format:  sshkey.Type(),
			Blob:    sshkey.Marshal(),
			Comment: x509cert.Subject.String(),
		})
	}
	return keys, err
}

func (self *pivAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if err := self.card.Lock(); err != nil {
		return nil, err
	}
	defer self.card.Unlock()

	if err := piv.SelectApp(self.card); err != nil {
		return nil, err
	}

	fp := key.Marshal()
	for _, k := range self.knownKeys {
		if bytes.Equal(fp, k.fp) {
			alg, err := piv.AlgorithmFromPublicKey(k.pub)
			if err != nil {
				return nil, err
			}

			pivSigner := piv.NewSigner(self.card, k.pub, k.id, alg)
			sshSigner, err := ssh.NewSignerFromSigner(pivSigner)
			if err != nil {
				return nil, err
			}

			var pinent *pinentry.Client
			defer func() {
				if pinent != nil {
					pinent.Shutdown()
				}
			}()

			for {
				signature, err := sshSigner.Sign(rand.Reader, data)
				switch {
				case protocol.IsLoginRequired(err):
					if pinent == nil {
						pinent, err = pinentry.Launch()
						if err != nil {
							return nil, err
						}
					}

					pinent.SetDesc(fmt.Sprintf("Authenticating with %s key", k.id.GetInfo().Name))
					pinent.SetPrompt("PIN:")

				pinLoop:
					for {
						pin, err := pinent.GetPIN()
						if err != nil {
							return nil, err
						}

						err = piv.Login(self.card, piv.ApplicationPIN, []byte(pin))
						switch {
						case protocol.PinAttempts(err) > 0:
							pinent.SetRepeatPrompt(
								fmt.Sprintf("%d attempts remaining", protocol.PinAttempts(err)))
							continue
						case err != nil:
							return nil, errors.Wrap(err, "Logging in")
						default:
							break pinLoop
						}
					}
				case err != nil:
					return nil, errors.Wrap(err, "Signing")
				default:
					err := sshSigner.PublicKey().Verify(data, signature)
					if err != nil {
						return nil, err
					}
					return signature, nil
				}
			}
		}
	}
	return nil, errors.New("Key not found")
}

func (self *pivAgent) Add(key agent.AddedKey) error {
	return errors.New("Cannot add keys to smartcard")
}

func (self *pivAgent) Remove(key ssh.PublicKey) error {
	return errors.New("Cannot remove keys from smartcard")
}

func (self *pivAgent) RemoveAll() error {
	return errors.New("Cannot remove keys from smartcard")
}

func (self *pivAgent) Lock(passphrase []byte) error {
	return piv.Logout(self.card)
}

func (self *pivAgent) Unlock(passphrase []byte) error {
	return nil
}

func (self *pivAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("Not implemented")
}

type pivConfig struct {
	Transport string `json:"transport"`
}

func pivFactory(params json.RawMessage) (agent.Agent, error) {
	var config pivConfig
	if err := json.Unmarshal(params, &config); err != nil {
		return nil, err
	}

	t, err := protocol.CreateTransport(config.Transport)
	if err != nil {
		return nil, err
	}

	c := protocol.NewCard(t)

	return NewAgent(c), nil
}

func init() {
	emissary.RegisterBackend("piv", pivFactory)
}
