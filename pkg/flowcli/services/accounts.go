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

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/onflow/flow-cli/pkg/flowcli"
	"github.com/onflow/flow-cli/pkg/flowcli/output"
	"github.com/onflow/flow-cli/pkg/flowcli/project"

	"github.com/onflow/cadence"

	"github.com/onflow/flow-cli/pkg/flowcli/config"
	"github.com/onflow/flow-cli/pkg/flowcli/gateway"
	"github.com/onflow/flow-cli/pkg/flowcli/util"
	tmpl "github.com/onflow/flow-core-contracts/lib/go/templates"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/templates"
)

// Accounts service handles all interactions for accounts
type Accounts struct {
	gateway gateway.Gateway
	project *project.Project
	logger  output.Logger
}

// NewAccounts create new account service
func NewAccounts(
	gateway gateway.Gateway,
	project *project.Project,
	logger output.Logger,
) *Accounts {
	return &Accounts{
		gateway: gateway,
		project: project,
		logger:  logger,
	}
}

// Get gets an account based on address
func (a *Accounts) Get(address string) (*flow.Account, error) {
	a.logger.StartProgress(fmt.Sprintf("Loading %s...", address))

	flowAddress := flow.HexToAddress(
		strings.ReplaceAll(address, "0x", ""),
	)

	account, err := a.gateway.GetAccount(flowAddress)
	a.logger.StopProgress("")

	return account, err
}

func (a *Accounts) Add(
	name string,
	accountAddress string,
	signatureAlgorithm string,
	hashingAlgorithm string,
	keyIndex int,
	keyHex string,
	overwrite bool,
	path []string,
) (*project.Account, error) {
	if a.project == nil {
		return nil, fmt.Errorf("missing configuration, initialize it: flow project init")
	}

	existingAccount := a.project.GetAccountByName(name)
	if existingAccount != nil && !overwrite {
		return nil, fmt.Errorf("account with name [%s] already exists in the config, use `overwrite` if you want to overwrite it", name)
	}

	sigAlgo, hashAlgo, err := util.ConvertSigAndHashAlgo(signatureAlgorithm, hashingAlgorithm)
	if err != nil {
		return nil, err
	}

	if keyIndex < 0 {
		return nil, fmt.Errorf("key index must be positive number")
	}

	address := flow.HexToAddress(accountAddress)
	chainID, err := util.GetAddressNetwork(address)
	if err != nil {
		return nil, err
	}

	confAccount := config.Account{
		Name:    name,
		Address: address,
		ChainID: chainID,
	}

	accountKey := config.AccountKey{
		Index:    keyIndex,
		SigAlgo:  sigAlgo,
		HashAlgo: hashAlgo,
	}

	// TODO: refactor this to models
	//  as it will lead to code duplication when creating accounts elsewhere
	//  key context could/should be abstracted from implementation here
	if keyHex != "" {
		_, err := crypto.DecodePrivateKeyHex(sigAlgo, keyHex)
		if err != nil {
			return nil, fmt.Errorf("key hex could not be parsed")
		}

		accountKey.Type = config.KeyTypeHex
		accountKey.Context = make(map[string]string)
		accountKey.Context[config.PrivateKeyField] = keyHex

	} else {
		return nil, fmt.Errorf("private key must be provided")
	}

	confAccount.Keys = []config.AccountKey{accountKey}

	account, err := project.AccountFromConfig(confAccount)
	if err != nil {
		return nil, err
	}
	// TODO: refactor context
	sig, err := account.DefaultKey().Signer(context.Background())
	if err != nil {
		return nil, err
	}

	_, err = sig.Sign([]byte("test"))
	if err != nil {
		return nil, fmt.Errorf("could not sign with the new key")
	}

	a.project.AddOrUpdateAccount(account)

	err = a.project.Save(path[0]) // only allow saving to one config for now
	if err != nil {
		return nil, err
	}

	a.logger.Info("Account added to configuration\n")

	return account, nil
}

// StakingInfo gets staking info for the account
func (a *Accounts) StakingInfo(accountAddress string) (*cadence.Value, *cadence.Value, error) {
	a.logger.StartProgress(fmt.Sprintf("Fetching info for %s...", accountAddress))

	address := flow.HexToAddress(
		strings.ReplaceAll(accountAddress, "0x", ""),
	)

	cadenceAddress := []cadence.Value{cadence.NewAddress(address)}

	chain, err := util.GetAddressNetwork(address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine network from address, check the address and network")
	}

	if chain == flow.Emulator {
		return nil, nil, fmt.Errorf("emulator chain not supported")
	}

	env := util.EnvFromNetwork(chain)

	stakingInfoScript := tmpl.GenerateGetLockedStakerInfoScript(env)
	delegationInfoScript := tmpl.GenerateGetLockedDelegatorInfoScript(env)

	stakingValue, err := a.gateway.ExecuteScript(stakingInfoScript, cadenceAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting staking info: %s", err.Error())
	}

	delegationValue, err := a.gateway.ExecuteScript(delegationInfoScript, cadenceAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting delegation info: %s", err.Error())
	}

	a.logger.StopProgress("")

	return &stakingValue, &delegationValue, nil
}

// Create creates an account with signer name, keys, algorithms, contracts and returns the new account
func (a *Accounts) Create(
	signerName string,
	keys []string,
	signatureAlgorithm string,
	hashingAlgorithm string,
	contracts []string,
) (*flow.Account, error) {
	if a.project == nil {
		return nil, fmt.Errorf("missing configuration, initialize it: flow project init")
	}

	signer := a.project.GetAccountByName(signerName)
	if signer == nil {
		return nil, fmt.Errorf("signer account: [%s] doesn't exists in configuration", signerName)
	}

	a.logger.StartProgress("Creating Account...")

	accountKeys := make([]*flow.AccountKey, len(keys))

	sigAlgo, hashAlgo, err := util.ConvertSigAndHashAlgo(signatureAlgorithm, hashingAlgorithm)
	if err != nil {
		return nil, err
	}

	for i, publicKeyHex := range keys {
		publicKey, err := crypto.DecodePublicKeyHex(
			sigAlgo,
			strings.ReplaceAll(publicKeyHex, "0x", ""),
		)
		if err != nil {
			return nil, fmt.Errorf("could not decode public key for key: %s, with signature algorith: %s", publicKeyHex, sigAlgo)
		}

		accountKeys[i] = &flow.AccountKey{
			PublicKey: publicKey,
			SigAlgo:   sigAlgo,
			HashAlgo:  hashAlgo,
			Weight:    flow.AccountKeyWeightThreshold,
		}
	}

	var contractTemplates []templates.Contract

	for _, contract := range contracts {
		contractFlagContent := strings.SplitN(contract, ":", 2)
		if len(contractFlagContent) != 2 {
			return nil, fmt.Errorf("wrong format for contract. Correct format is name:path, but got: %s", contract)
		}
		contractName := contractFlagContent[0]
		contractPath := contractFlagContent[1]

		contractSource, err := util.LoadFile(contractPath)
		if err != nil {
			return nil, err
		}

		contractTemplates = append(contractTemplates,
			templates.Contract{
				Name:   contractName,
				Source: string(contractSource),
			},
		)
	}

	tx := templates.CreateAccount(accountKeys, contractTemplates, signer.Address())
	tx, err = a.gateway.SendTransaction(tx, signer)
	if err != nil {
		return nil, err
	}

	a.logger.StopProgress("")

	a.logger.StartProgress("Waiting for transaction to be sealed...")

	result, err := a.gateway.GetTransactionResult(tx, true)
	if err != nil {
		return nil, err
	}

	a.logger.StopProgress("")

	events := flowcli.EventsFromTransaction(result)
	newAccountAddress := events.GetAddress()

	if newAccountAddress == nil {
		return nil, fmt.Errorf("new account address couldn't be fetched")
	}

	return a.gateway.GetAccount(*newAccountAddress)
}

// AddContract adds new contract to the account and returns the updated account
func (a *Accounts) AddContract(
	accountName string,
	contractName string,
	contractFilename string,
	updateExisting bool,
) (*flow.Account, error) {
	if a.project == nil {
		return nil, fmt.Errorf("missing configuration, initialize it: flow project init")
	}

	account := a.project.GetAccountByName(accountName)
	if account == nil {
		return nil, fmt.Errorf("account: [%s] doesn't exists in configuration", accountName)
	}

	return a.addContract(account, contractName, contractFilename, updateExisting)
}

// AddContractForAddress adds new contract to the address using private key specified
func (a *Accounts) AddContractForAddress(
	accountAddress string,
	accountPrivateKey string,
	contractName string,
	contractFilename string,
	updateExisting bool,
) (*flow.Account, error) {
	account, err := accountFromAddressAndKey(accountAddress, accountPrivateKey)
	if err != nil {
		return nil, err
	}

	return a.addContract(account, contractName, contractFilename, updateExisting)
}

func (a *Accounts) addContract(
	account *project.Account,
	contractName string,
	contractFilename string,
	updateExisting bool,
) (*flow.Account, error) {
	a.logger.StartProgress(
		fmt.Sprintf("Adding Contract '%s' to the account '%s'...", contractName, account.Address()),
	)

	// TODO: refactor this for same reasons as it is in addAccount and sendTransaction
	if account.DefaultKey().Type() == config.KeyTypeGoogleKMS {
		resourceID := account.DefaultKey().ToConfig().Context[config.KMSContextField]
		err := util.GcloudApplicationSignin(resourceID)
		if err != nil {
			return nil, err
		}
	}

	contractSource, err := util.LoadFile(contractFilename)
	if err != nil {
		return nil, err
	}

	tx := templates.AddAccountContract(
		account.Address(),
		templates.Contract{
			Name:   contractName,
			Source: string(contractSource),
		},
	)

	// if we are updating contract
	if updateExisting {
		tx = templates.UpdateAccountContract(
			account.Address(),
			templates.Contract{
				Name:   contractName,
				Source: string(contractSource),
			},
		)
	}

	// send transaction with contract
	tx, err = a.gateway.SendTransaction(tx, account)
	if err != nil {
		return nil, err
	}

	// we wait for transaction to be sealed
	trx, err := a.gateway.GetTransactionResult(tx, true)
	if err != nil {
		return nil, err
	}

	if trx.Error != nil {
		a.logger.Error("Deploying contract failed")
		return nil, trx.Error
	}

	update, err := a.gateway.GetAccount(account.Address())

	a.logger.StopProgress("")

	if updateExisting {
		a.logger.Info(fmt.Sprintf("Contract '%s' updated on the account '%s'.", contractName, account.Address()))
	} else {
		a.logger.Info(fmt.Sprintf("Contract '%s' deployed to the account '%s'.", contractName, account.Address()))
	}

	return update, err
}

// RemoveContracts removes a contract from the account
func (a *Accounts) RemoveContract(
	contractName string,
	accountName string,
) (*flow.Account, error) {
	account := a.project.GetAccountByName(accountName)
	if account == nil {
		return nil, fmt.Errorf("account: [%s] doesn't exists in configuration", accountName)
	}

	return a.removeContract(contractName, account)
}

// RemoveContractForAddress removes contract from address using private key
func (a *Accounts) RemoveContractForAddress(
	contractName string,
	accountAddress string,
	accountPrivateKey string,
) (*flow.Account, error) {
	account, err := accountFromAddressAndKey(accountAddress, accountPrivateKey)
	if err != nil {
		return nil, err
	}

	return a.removeContract(contractName, account)
}

func (a *Accounts) removeContract(
	contractName string,
	account *project.Account,
) (*flow.Account, error) {
	a.logger.StartProgress(
		fmt.Sprintf("Removing Contract %s from %s...", contractName, account.Address()),
	)

	tx := templates.RemoveAccountContract(account.Address(), contractName)
	tx, err := a.gateway.SendTransaction(tx, account)
	if err != nil {
		return nil, err
	}

	a.logger.StopProgress("")

	txr, err := a.gateway.GetTransactionResult(tx, true)
	if err != nil {
		return nil, err
	}
	if txr != nil && txr.Error != nil {
		a.logger.Error("Removing contract failed")
		return nil, txr.Error
	}

	a.logger.Info(fmt.Sprintf("Contract %s removed from account %s\n", contractName, account.Address()))

	return a.gateway.GetAccount(account.Address())
}

// AccountFromAddressAndKey get account from address and private key
func accountFromAddressAndKey(accountAddress string, accountPrivateKey string) (*project.Account, error) {
	address := flow.HexToAddress(
		strings.ReplaceAll(accountAddress, "0x", ""),
	)

	privateKey, err := crypto.DecodePrivateKeyHex(crypto.ECDSA_P256, accountPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key is not correct")
	}

	account := project.AccountFromAddressAndKey(address, privateKey)
	return account, nil
}