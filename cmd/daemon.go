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
	"io/ioutil"
	"os"
	"path"

	"github.com/spf13/cobra"
)

// daemonCmd represents the daemon command
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Starts the ssh-emissary daemon in the background",
	Long: `
	Starts the ssh-emissary as a daemon`,
	Run: runDaemon,
}

func runDaemon(cmd *cobra.Command, args []string) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting path to own executable: %s\n", err.Error())
		os.Exit(1)
	}

	dir, err := ioutil.TempDir(os.Getenv("XDG_RUNTIME_DIR"), "ssh-emissary")
	if err != nil {
		fmt.Printf("Error creating temporary directory: %s\n", err.Error())
		os.Exit(1)
	}

	sockPath := path.Join(dir, "ssh-agent")

	proc, err := os.StartProcess(exe, []string{exe, "serve", "--sock", sockPath}, &os.ProcAttr{Files: []*os.File{
		os.Stdin,
		os.Stderr,
		os.Stderr,
	}})

	if err != nil {
		fmt.Printf("Error starting agent: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("SSH_AUTH_SOCK=%s\n", sockPath)
	proc.Release()
}

func init() {
	rootCmd.AddCommand(daemonCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// daemonCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// daemonCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
