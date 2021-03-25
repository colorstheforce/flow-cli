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
	"fmt"
	"strings"

	"github.com/onflow/flow-cli/pkg/flowcli"
	"github.com/onflow/flow-cli/pkg/flowcli/output"
	"github.com/onflow/flow-cli/pkg/flowcli/project"

	"github.com/onflow/flow-cli/pkg/flowcli/config"
	"github.com/onflow/flow-cli/pkg/flowcli/gateway"
	"github.com/onflow/flow-cli/pkg/flowcli/util"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/crypto"
)

// Scripts service handles all interactions for transactions
type Transactions struct {
	gateway gateway.Gateway
	project *project.Project
	logger  output.Logger
}

// NewTransactions create new transaction service
func NewTransactions(
	gateway gateway.Gateway,
	project *project.Project,
	logger output.Logger,
) *Transactions {
	return &Transactions{
		gateway: gateway,
		project: project,
		logger:  logger,
	}
}

// Send transaction
func (t *Transactions) Send(
	transactionFilename string,
	signerName string,
	args []string,
	argsJSON string,
) (*flow.Transaction, *flow.TransactionResult, error) {
	if t.project == nil {
		return nil, nil, fmt.Errorf("missing configuration, initialize it: flow project init")
	}

	signer := t.project.GetAccountByName(signerName)
	if signer == nil {
		return nil, nil, fmt.Errorf("signer account: [%s] doesn't exists in configuration", signerName)
	}

	return t.send(transactionFilename, signer, args, argsJSON)
}

// SendForAddress send transaction for address and private key specified
func (t *Transactions) SendForAddress(
	transactionFilename string,
	signerAddress string,
	signerPrivateKey string,
	args []string,
	argsJSON string,
) (*flow.Transaction, *flow.TransactionResult, error) {
	address := flow.HexToAddress(signerAddress)

	privateKey, err := crypto.DecodePrivateKeyHex(crypto.ECDSA_P256, signerPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("private key is not correct")
	}

	account := project.AccountFromAddressAndKey(address, privateKey)

	return t.send(transactionFilename, account, args, argsJSON)
}

func (t *Transactions) send(
	transactionFilename string,
	signer *project.Account,
	args []string,
	argsJSON string,
) (*flow.Transaction, *flow.TransactionResult, error) {

	// if google kms account then sign in TODO discuss refactor - move to account
	if signer.DefaultKey().Type() == config.KeyTypeGoogleKMS {
		resourceID := signer.DefaultKey().ToConfig().Context[config.KMSContextField]
		err := util.GcloudApplicationSignin(resourceID)
		if err != nil {
			return nil, nil, err
		}
	}

	code, err := util.LoadFile(transactionFilename)
	if err != nil {
		return nil, nil, err
	}

	t.logger.StartProgress("Sending Transaction...")

	tx := flow.NewTransaction().
		SetScript(code).
		AddAuthorizer(signer.Address())

	transactionArguments, err := flowcli.ParseArguments(args, argsJSON)
	if err != nil {
		return nil, nil, err
	}

	for _, arg := range transactionArguments {
		err := tx.AddArgument(arg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to add %s argument to a transaction", transactionFilename)
		}
	}

	t.logger.Info(fmt.Sprintf("Sending transaction with ID %s", tx.ID()))

	tx, err = t.gateway.SendTransaction(tx, signer)
	if err != nil {
		return nil, nil, err
	}

	t.logger.StartProgress("Waiting for transaction to be sealed...")

	res, err := t.gateway.GetTransactionResult(tx, true)

	t.logger.StopProgress("")

	return tx, res, err
}

// GetStatus of transaction
func (t *Transactions) GetStatus(
	transactionID string,
	waitSeal bool,
) (*flow.Transaction, *flow.TransactionResult, error) {
	txID := flow.HexToID(
		strings.ReplaceAll(transactionID, "0x", ""),
	)

	t.logger.StartProgress("Fetching Transaction...")

	tx, err := t.gateway.GetTransaction(txID)
	if err != nil {
		return nil, nil, err
	}

	if waitSeal {
		t.logger.StartProgress("Waiting for transaction to be sealed...")
	}

	result, err := t.gateway.GetTransactionResult(tx, waitSeal)

	t.logger.StopProgress("")

	return tx, result, err
}