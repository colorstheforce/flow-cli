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

package cli

import (
	"context"
	"fmt"
	"github.com/onflow/flow-go-sdk/client"
	"google.golang.org/grpc"
	"os"
	"strings"

	"github.com/onflow/flow-go-sdk"
)

func SendTransaction(projectConf *Config, tx *flow.Transaction, host string, signers string, withResults bool) {
	ctx := context.Background()
	host = projectConf.HostWithOverride(host)

	flowClient, err := client.New(host, grpc.WithInsecure())
	if err != nil {
		Exitf(1, "Failed to connect to host: %s", err)
	}

	// Get Service Account and validate it's keys
	serviceAccount := projectConf.Accounts[serviceAccountName]
	validateKeyPreReq(serviceAccount)

	argsList := strings.ReplaceAll(signers, " ", "")
	addresses := strings.Split(argsList, "|")

	signerAccount := serviceAccount
	for i, address := range addresses {
		account := projectConf.Accounts[address]

		if account != nil {
			validateKeyPreReq(account)
		} else {
			// TODO: check address, if it's not Flow Address - quit app
			fmt.Printf("Getting information for account with address 0x%s ...\n", WithPrefix(address).Hex())
			account = signerAccount
		}

		// flowAddress := flow.BytesToAddress([]byte(address))
		// TODO: we need to make sure we are passing specified address and not service account again...
		tx.AddAuthorizer(account.Address)

		if i == 0 {
			// TODO: first key should sign the envelope
			signerAccount = account
			flowAccount, err := flowClient.GetAccount(ctx, signerAccount.Address)
			if err != nil {
				Exitf(1, "Failed to get account with address %s: 0x%s", signerAddress.Hex(), err)
			}

			accountKey := flowAccount.Keys[signerAccount.KeyIndex]

			sealed, err := flowClient.GetLatestBlockHeader(ctx, true)
			if err != nil {
				Exitf(1, "Failed to get latest sealed block: %s", err)
			}

			tx.
				SetReferenceBlockID(sealed.ID).
				SetProposalKey(account.Address, accountKey.Index, accountKey.SequenceNumber).
				SetPayer(signerAccount.Address)
		}

		tx.SignPayload()
	}

	/*	// Signers
		var accounts []*Account

		argsList := strings.ReplaceAll(signers, " ", "")
		addresses := strings.Split(argsList, "|")

		for _, address := range addresses {


			type Account struct {
				KeyType    KeyType
				KeyIndex   int
				KeyContext map[string]string
				Address    flow.Address
				PrivateKey crypto.PrivateKey
				SigAlgo    crypto.SignatureAlgorithm
				HashAlgo   crypto.HashAlgorithm
				Signer     crypto.Signer
			}


			var signerAccount *Account
			if address == "service" {
				signerAccount = projectConf.Accounts[address]
			} else {
				flowAddress := flow.BytesToAddress([]byte(address))
				hexAddress := flowAddress.Hex()

				fmt.Printf("Getting information for account with address 0x%s ...\n", hexAddress)
				signerAccount = GetAccount(host, flowAddress)
				if err != nil {
					Exitf(1, "Failed to get account with address %s: 0x%s", hexAddress, err)
				}
			}

			validateKeyPreReq(signerAccount)
			accounts = append(accounts, signerAccount)

			tx.AddAuthorizer(signerAccount.Address)
			fmt.Printf("Address added: %s \n", address)
		}

		// Service account
		serviceAccount := projectConf.Accounts["service"]
		validateKeyPreReq(serviceAccount)

		// []*Account
		signerAccount := serviceAccount
		if len(signers) > 0 {
			signerAccount = signers[0]
		}

		signerAddress := serviceAccount.Address



		// Default 0, i.e. first key
		accountKey := account.Keys[signerAccount.KeyIndex]

		sealed, err := flowClient.GetLatestBlockHeader(ctx, true)
		if err != nil {
			Exitf(1, "Failed to get latest sealed block: %s", err)
		}

		tx.SetReferenceBlockID(sealed.ID).
			SetProposalKey(signerAddress, accountKey.Index, accountKey.SequenceNumber).
			SetPayer(signerAddress)

		err = tx.SignEnvelope(signerAddress, accountKey.Index, signerAccount.Signer)
		if err != nil {
			Exitf(1, "Failed to sign transaction: %s", err)
		}

		fmt.Printf("Submitting transaction with ID %s ...\n", tx.ID())

		err = flowClient.SendTransaction(context.Background(), *tx)
		if err == nil {
			fmt.Printf("Successfully submitted transaction with ID %s\n", tx.ID())
		} else {
			Exitf(1, "Failed to submit transaction: %s", err)
		}
		if withResults {
			res, err := waitForSeal(ctx, flowClient, tx.ID())
			if err != nil {
				Exitf(1, "Failed to seal transaction: %s", err)
			}
			printTxResult(tx, res, true)
		}*/
}

func validateKeyPreReq(account *Account) {
	if account.KeyType == KeyTypeHex {
		// Always Valid
		return
	} else if account.KeyType == KeyTypeKMS {
		// Check GOOGLE_APPLICATION_CREDENTIALS
		googleAppCreds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		if len(googleAppCreds) == 0 {
			if len(account.KeyContext["projectId"]) == 0 {
				Exitf(1, "Could not get GOOGLE_APPLICATION_CREDENTIALS, no google service account json provided but private key type is KMS", account.Address)
			}
			GcloudApplicationSignin(account.KeyContext["projectId"])
		}
		return
	}
	Exitf(1, "Failed to validate %s key for %s", account.KeyType, account.Address)
}
