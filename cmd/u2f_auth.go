// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"strings"
	"time"

	"github.com/erincandescent/ssh-emissary/lib"
	"github.com/erincandescent/ssh-emissary/u2fproxy"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type authReq struct {
	u2ftoken.AuthenticateRequest
	PublicKey []byte
}

// authCmd represents the auth command
var u2fAuthCmd = &cobra.Command{
	Use:   "u2f-auth",
	Short: "Do a test authorization",
	Long:  `Does a test authorization against the specified file`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := lib.ConnectAgent()
		if err != nil {
			return err
		}

		body, err := ioutil.ReadFile(args[0])
		if err != nil {
			return errors.Wrapf(err, "Reading %s", args[0])
		}

		appId := sha256.Sum256([]byte("urn:example"))
		challenge := make([]byte, 32)
		io.ReadFull(rand.Reader, challenge)

		fmt.Println("Challenge: ", hex.EncodeToString(challenge))
		fmt.Println("AppID: ", hex.EncodeToString(appId[:]))

		// Parse key file
		lines := strings.Split(string(body), "\n")
		var reqs []authReq
		for i := 0; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			if ix := strings.IndexByte(line, ':'); ix != -1 {
				line = line[ix+1:]
			}
			enc := base64.RawStdEncoding

			splitPos := strings.IndexByte(line, ',')
			if splitPos == -1 {
				return errors.New("Unable to find comma on key line")
			}

			pubKey, err := enc.DecodeString(line[0:splitPos])
			if err != nil {
				return errors.Wrap(err, "Decoding public key")
			}
			keyHandle, err := enc.DecodeString(line[splitPos+1:])
			if err != nil {
				return errors.Wrap(err, "Decoding key handle")
			}

			req := authReq{
				AuthenticateRequest: u2ftoken.AuthenticateRequest{
					Challenge:   challenge,
					Application: appId[:],
					KeyHandle:   keyHandle,
				},
				PublicKey: pubKey,
			}

			reqs = append(reqs, req)
		}

		keys, err := a.List()
		if err != nil {
			return errors.Wrap(err, "Getting keys from agent")
		}

		var foundToken *u2ftoken.Token
		var req authReq

	findToken:
		for i := 0; i < len(keys); i++ {
			key := keys[i]
			if key.Format != "u2f" {
				continue
			}

			dev := u2fproxy.NewProxyDevice(a, *key)
			token := u2ftoken.NewToken(dev)

			for j := 0; j < len(reqs); j++ {
				err := token.CheckAuthenticate(reqs[j].AuthenticateRequest)
				if err == u2ftoken.ErrUnknownKeyHandle {
					continue
				} else if err != nil {
					return errors.Wrap(err, "Talking to key")
				} else {
					foundToken = token
					req = reqs[j]
					break findToken
				}
			}
		}

		if foundToken == nil {
			return errors.New("Unable to find any registered token")
		}

		x, y := elliptic.Unmarshal(elliptic.P256(), req.PublicKey)
		if x == nil {
			return errors.New("Error unmarshalling private key")
		}
		pubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

		fmt.Println("Please touch your token...")
		for {
			resp, err := foundToken.Authenticate(req.AuthenticateRequest)
			if err == u2ftoken.ErrPresenceRequired {
				time.Sleep(200 * time.Millisecond)
				continue
			} else if err != nil {
				return err
			}

			var baseString []byte
			baseString = append(appId[:],
				0x01, // User presence
				byte(resp.Counter>>24),
				byte(resp.Counter>>16),
				byte(resp.Counter>>8),
				byte(resp.Counter))
			baseString = append(baseString, challenge...)
			digest := sha256.Sum256(baseString)

			fmt.Println("Response:", hex.EncodeToString(resp.RawResponse))

			var sig struct {
				R, S *big.Int
			}
			_, err = asn1.Unmarshal(resp.Signature, &sig)
			if err != nil {
				return errors.Wrap(err, "Error unmarshalling signature")
			}

			if ecdsa.Verify(&pubKey, digest[:], sig.R, sig.S) {
				fmt.Println("OK!")
				return nil
			} else {
				return errors.New("Error verifying signature")
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(u2fAuthCmd)
}
