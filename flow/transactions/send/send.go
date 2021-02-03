/*
 * Flow CLI
 *
 * Copyright 2019-2020 Dapper Labs, Inc.
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

package send

import (
	cli "github.com/onflow/flow-cli/flow"
	"github.com/onflow/flow-go-sdk"
	"github.com/psiemens/sconfig"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
)

type Config struct {
	Signer  string `default:"service" flag:"signer,s"`
	Code    string `flag:"code,c" info:"path to Cadence file"`
	Args    string `flag:"args" info:"arguments to pass to transaction"`
	Host    string `flag:"host" info:"Flow Access API host address"`
	Results bool   `default:"false" flag:"results" info:"Display the results of the transaction"`
}

var conf Config

var Cmd = &cobra.Command{
	Use:     "send",
	Short:   "Send a transaction",
	Example: `flow transactions send --code=./tx.cdc --signer="service | 01cf0e2f2f715450" --args="[{\"type\": \"String\", \"value\": \"Hello, Cadence\"}]"`,
	Run: func(cmd *cobra.Command, args []string) {
		projectConf := cli.LoadConfig()

		var (
			code []byte
			err  error
		)

		tx := flow.NewTransaction()

		// Code
		if conf.Code != "" {
			code, err = ioutil.ReadFile(conf.Code)
			if err != nil {
				cli.Exitf(1, "Failed to read transaction script from %s", conf.Code)
			}
		}
		tx.SetScript(code)

		// Arguments
		if conf.Args != "" {
			transactionArguments, err := cli.ParseArguments(conf.Args)
			if err != nil {
				cli.Exitf(1, "Invalid arguments passed: %s", conf.Args)
			}
			for _, arg := range transactionArguments {
				err := tx.AddArgument(arg)

				if err != nil {
					cli.Exitf(1, "Failed to add %s argument to a transaction ", conf.Code)
				}
			}
		}

		cli.SendTransaction(
			projectConf,
			tx,
			conf.Host,
			conf.Signer,
			conf.Results,
		)
	},
}

func init() {
	initConfig()
}

func initConfig() {
	err := sconfig.New(&conf).
		FromEnvironment(cli.EnvPrefix).
		BindFlags(Cmd.PersistentFlags()).
		Parse()
	if err != nil {
		log.Fatal(err)
	}
}
