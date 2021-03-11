package emulator

import (
	"github.com/onflow/flow-cli/flow/cli"
	"github.com/onflow/flow-cli/flow/cli/keys"
	"github.com/onflow/flow-cli/flow/config"
	"github.com/onflow/flow-emulator/cmd/emulator/start"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:              "emulator",
	Short:            "Flow emulator server",
	TraverseChildren: true,
}

func configuredServiceKey(
	_ bool,
	_ crypto.SignatureAlgorithm,
	_ crypto.HashAlgorithm,
) (
	crypto.PrivateKey,
	crypto.SignatureAlgorithm,
	crypto.HashAlgorithm,
) {
	project, err := cli.LoadProject(cli.ConfigPath)
	if err != nil {
		cli.Exitf(1, err.Error())
	}

	serviceAccount, _ := project.EmulatorServiceAccount()

	serviceKeyHex, ok := serviceAccount.DefaultKey().(*keys.HexAccountKey)
	if !ok {
		cli.Exit(1, "Only hexadecimal keys can be used as the emulator service account key.")
	}

	privateKey, err := crypto.DecodePrivateKeyHex(serviceKeyHex.SigAlgo(), serviceKeyHex.PrivateKeyHex())
	if err != nil {
		cli.Exitf(
			1,
			"Invalid private key in \"%s\" emulator configuration",
			config.DefaultEmulatorConfigName,
		)
	}

	return privateKey, serviceKeyHex.SigAlgo(), serviceKeyHex.HashAlgo()
}

func init() {
	Cmd = start.Cmd(configuredServiceKey)
	Cmd.Use = "emulator"
}