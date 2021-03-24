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

package project

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/onflow/flow-cli/pkg/flowcli/util"

	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/spf13/afero"
	"github.com/thoas/go-funk"

	"github.com/onflow/flow-cli/pkg/flowcli/config"
	"github.com/onflow/flow-cli/pkg/flowcli/config/json"
)

var DefaultConfigPath = "flow.json"

// Project has all the funcionality to manage project
type Project struct {
	composer *config.Loader
	conf     *config.Config
	accounts []*Account
}

// LoadProject loads configuration and setup the project
func LoadProject(configFilePath []string) (*Project, error) {
	composer := config.NewLoader(afero.NewOsFs())

	// here we add all available parsers (more to add yaml etc...)
	composer.AddConfigParser(json.NewParser())
	conf, err := composer.Load(configFilePath)

	if err != nil {
		if errors.Is(err, config.ErrDoesNotExist) {
			return nil, err
		}

		return nil, fmt.Errorf("failed to open project configuration: %s", configFilePath)
	}

	proj, err := newProject(conf, composer)
	if err != nil {
		return nil, fmt.Errorf("invalid project configuration: %s", err)
	}

	return proj, nil
}

// ProjectExists checks if project exists
func ProjectExists(path string) bool {
	return config.Exists(path)
}

// InitProject initializes the project
func InitProject(sigAlgo crypto.SignatureAlgorithm, hashAlgo crypto.HashAlgorithm) (*Project, error) {
	emulatorServiceAccount, err := generateEmulatorServiceAccount(sigAlgo, hashAlgo)

	composer := config.NewLoader(afero.NewOsFs())
	composer.AddConfigParser(json.NewParser())

	return &Project{
		composer: composer,
		conf:     defaultConfig(emulatorServiceAccount),
		accounts: []*Account{emulatorServiceAccount},
	}, err
}

const (
	defaultEmulatorNetworkName        = "emulator"
	defaultEmulatorServiceAccountName = "emulator-account"
	defaultEmulatorPort               = 3569
	defaultEmulatorHost               = "127.0.0.1:3569"
)

func defaultConfig(defaultEmulatorServiceAccount *Account) *config.Config {
	return &config.Config{
		Emulators: config.Emulators{{
			Name:           config.DefaultEmulatorConfigName,
			ServiceAccount: defaultEmulatorServiceAccount.name,
			Port:           defaultEmulatorPort,
		}},
		Networks: config.Networks{{
			Name:    defaultEmulatorNetworkName,
			Host:    defaultEmulatorHost,
			ChainID: flow.Emulator,
		}},
	}
}

func generateEmulatorServiceAccount(sigAlgo crypto.SignatureAlgorithm, hashAlgo crypto.HashAlgorithm) (*Account, error) {
	seed, err := util.RandomSeed(crypto.MinSeedLength)
	if err != nil {
		return nil, err
	}

	privateKey, err := crypto.GeneratePrivateKey(sigAlgo, seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate emulator service key: %v", err)
	}

	serviceAccountKey := NewHexAccountKeyFromPrivateKey(0, hashAlgo, privateKey)

	return &Account{
		name:    defaultEmulatorServiceAccountName,
		address: flow.ServiceAddress(flow.Emulator),
		chainID: flow.Emulator,
		keys: []AccountKey{
			serviceAccountKey,
		},
	}, nil
}

func newProject(conf *config.Config, composer *config.Loader) (*Project, error) {
	accounts, err := accountsFromConfig(conf)
	if err != nil {
		return nil, err
	}

	return &Project{
		composer: composer,
		conf:     conf,
		accounts: accounts,
	}, nil
}

// CheckContractConflict checks if there is any contract duplication between accounts
// for now we don't allow two different accounts deploying same contract
func (p *Project) ContractConflictExists(network string) bool {
	contracts := p.GetContractsByNetwork(network)

	uniq := funk.Uniq(
		funk.Map(contracts, func(c Contract) string {
			return c.Name
		}).([]string),
	).([]string)

	all := funk.Map(contracts, func(c Contract) string {
		return c.Name
	}).([]string)

	return len(all) != len(uniq)
}

func (p *Project) DefaultHost(network string) string {
	if network == "" {
		network = defaultEmulatorNetworkName
	}

	return p.conf.Networks.GetByName(network).Host
}

func (p *Project) GetNetworkByName(name string) *config.Network {
	return p.conf.Networks.GetByName(name)
}

func (p *Project) Host(network string) string {
	return p.conf.Networks.GetByName(network).Host
}

func (p *Project) EmulatorServiceAccount() (*Account, error) {
	emulator := p.conf.Emulators.GetDefault()
	acc := p.conf.Accounts.GetByName(emulator.ServiceAccount)
	return AccountFromConfig(*acc)
}

func (p *Project) SetEmulatorServiceKey(privateKey crypto.PrivateKey) {
	acc := p.accounts[0]
	key := acc.DefaultKey()
	acc.keys[0] = NewHexAccountKeyFromPrivateKey(key.Index(), key.HashAlgo(), privateKey)
}

func (p *Project) GetContractsByNetwork(network string) []Contract {
	contracts := make([]Contract, 0)

	// get deployments for specific network
	for _, deploy := range p.conf.Deployments.GetByNetwork(network) {
		account := p.GetAccountByName(deploy.Account)

		// go through each contract for this deploy
		for _, contractName := range deploy.Contracts {
			c := p.conf.Contracts.GetByNameAndNetwork(contractName, network)

			contract := Contract{
				Name:   c.Name,
				Source: path.Clean(c.Source),
				Target: account.address,
			}

			contracts = append(contracts, contract)
		}
	}

	return contracts
}

func (p *Project) GetAllAccountNames() []string {
	names := make([]string, 0)

	for _, account := range p.accounts {
		if !util.StringContains(names, account.name) {
			names = append(names, account.name)
		}
	}

	return names
}

func (p *Project) GetAccountByName(name string) *Account {
	var account *Account

	for _, acc := range p.accounts {
		if acc.name == name {
			account = acc
		}
	}

	return account
}

func (p *Project) AddAccount(account *Account) {
	p.accounts = append(p.accounts, account)
}

func (p *Project) AddOrUpdateAccount(account *Account) {
	for i, existingAccount := range p.accounts {
		if existingAccount.name == account.name {
			(*p).accounts[i] = account
			return
		}
	}

	p.accounts = append(p.accounts, account)
}

func (p *Project) GetAccountByAddress(address string) *Account {
	for _, account := range p.accounts {
		if account.address.String() == strings.ReplaceAll(address, "0x", "") {
			return account
		}
	}

	return nil
}

func (p *Project) GetAliases(network string) map[string]string {
	aliases := make(map[string]string)

	// get all contracts for selected network and if any has an address as target make it an alias
	for _, contract := range p.conf.Contracts.GetByNetwork(network) {
		if contract.IsAlias() {
			aliases[path.Clean(contract.Source)] = contract.Alias
		}
	}

	return aliases
}

func (p *Project) Save(path string) error {
	p.conf.Accounts = accountsToConfig(p.accounts)
	err := p.composer.Save(p.conf, path)

	if err != nil {
		return fmt.Errorf("failed to save project configuration to: %s", path)
	}

	return nil
}

type Contract struct {
	Name   string
	Source string
	Target flow.Address
}