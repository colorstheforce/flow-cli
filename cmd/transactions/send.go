/*
 * Flow CLI
 *
 * Copyright 2019-2021 Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package transactions

import (
	"github.com/onflow/flow-cli/cmd"
	"github.com/onflow/flow-cli/flow/lib"
	"github.com/onflow/flow-cli/flow/services"
	"github.com/psiemens/sconfig"
	"github.com/spf13/cobra"
)

type flagsSend struct {
	ArgsJSON string   `default:"" flag:"argsJSON" info:"arguments in JSON-Cadence format"`
	Args     []string `default:"" flag:"arg" info:"argument in Type:Value format"`
	Signer   string   `default:"emulator-account" flag:"signer,s"`
}

type cmdSend struct {
	cmd   *cobra.Command
	flags flagsSend
}

// NewSendCmd new send command
func NewSendCmd() cmd.Command {
	return &cmdSend{
		cmd: &cobra.Command{
			Use:     "send <filename>",
			Short:   "Send a transaction",
			Example: `flow transactions send tx.cdc --args String:"Hello world"`,
		},
	}
}

// Run command
func (a *cmdSend) Run(
	cmd *cobra.Command,
	args []string,
	project *lib.Project,
	services *services.Services,
) (cmd.Result, error) {
	tx, result, err := services.Transactions.Send(args[0], a.flags.Signer, a.flags.Args, a.flags.ArgsJSON)
	return &TransactionResult{
		result: result,
		tx:     tx,
	}, err
}

// GetFlags for transactions command
func (a *cmdSend) GetFlags() *sconfig.Config {
	return sconfig.New(&a.flags)
}

// GetCmd gets command
func (a *cmdSend) GetCmd() *cobra.Command {
	return a.cmd
}