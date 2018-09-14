// Copyright © 2018 Erin Shepherd <erin.shepherd@e43.eu>
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
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"

	"github.com/erincandescent/ssh-emissary/emissary"
	"github.com/spf13/cobra"
	sshagent "golang.org/x/crypto/ssh/agent"
	tilde "gopkg.in/mattes/go-expand-tilde.v1"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		sockPath, err := cmd.Flags().GetString("sock")
		if err != nil {
			return err
		}

		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			return err
		}

		home, err := tilde.Home()
		if err != nil {
			return err
		}

		configPath := path.Join(home, ".config", "ssh-emissary", "config.json")
		f, err := os.Open(configPath)
		if err != nil {
			return err
		}
		defer f.Close()

		conf, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		agent, err := emissary.Create(conf)
		if err != nil {
			return err
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("Error accepting: %s\n", err.Error())
				os.Exit(1)
			}
			go serveConnection(agent, conn)
		}
	},
}

func serveConnection(agent sshagent.Agent, conn net.Conn) {
	err := sshagent.ServeAgent(agent, conn)
	if err != io.EOF {
		fmt.Printf("Error serving connection: %s\n", err)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("sock", "", "Socket path to listen on")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
