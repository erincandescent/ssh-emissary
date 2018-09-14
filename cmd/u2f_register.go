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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/flynn/u2f/u2ftoken"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"

	"github.com/erincandescent/ssh-emissary/lib"
	"github.com/erincandescent/ssh-emissary/u2fproxy"
)

// u2fRegisterCmd represents the u2f-register command
var u2fRegisterCmd = &cobra.Command{
	Use:   "u2f-register",
	Short: "Register a U2F token",
	Long:  `Register a new U2F token for use as an authorized key on this machine`,
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := lib.ConnectAgent()
		if err != nil {
			return err
		}

		keys, err := a.List()
		if err != nil {
			return err
		}

		var u2fkeys []*agent.Key
		for i := 0; i < len(keys); i++ {
			if keys[i].Format == "u2f" {
				u2fkeys = append(u2fkeys, keys[i])
			}
		}

		if len(u2fkeys) == 0 {
			return errors.New("No U2F keys connected to agent\n")
		}

		fmt.Println("Registering, touch a key...")

		appId := sha256.Sum256([]byte("urn:example"))

		for {
			for i := 0; i < len(u2fkeys); i++ {
				dev := u2fproxy.NewProxyDevice(a, *keys[i])
				tok := u2ftoken.NewToken(dev)

				regReq := u2ftoken.RegisterRequest{}
				regReq.Application = appId[:]
				regReq.Challenge = make([]byte, 32)
				io.ReadFull(rand.Reader, regReq.Challenge)

				res, err := tok.Register(regReq)
				if err == u2ftoken.ErrPresenceRequired {
					continue
				} else if err != nil {
					log.Fatal(err)
				}

				pubKey := res[1:66]
				khLen := res[66]
				kh := res[67 : 67+khLen]

				enc := base64.RawStdEncoding
				fmt.Printf("%s:%s,%s\n", os.Getenv("USER"), enc.EncodeToString(pubKey), enc.EncodeToString(kh))
				return nil
			}

			time.Sleep(200 * time.Millisecond)
		}
	},
}

func init() {
	rootCmd.AddCommand(u2fRegisterCmd)
}
