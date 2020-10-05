package get

import (
	"fmt"
	"log"

	"github.com/onflow/flow-go-sdk"
	"github.com/psiemens/sconfig"
	"github.com/spf13/cobra"

	cli "github.com/dapperlabs/flow-cli/flow"
)

type Config struct {
	Host        string `default:"127.0.0.1:3569" flag:"host" info:"Flow Observation API host address"`
	Latest      bool   `default:"false" flag:"latest" info:"Display latest block"`
	BlockID     string `default:"" flag:"id" info:"Display block by id"`
	BlockHeight uint64 `default:"0" flag:"height" info:"Display block by height"`
}

var conf Config

var Cmd = &cobra.Command{
	Use:   "get <block_id>",
	Short: "Get block info",
	Run: func(cmd *cobra.Command, args []string) {
		var block *flow.Block
		if conf.Latest {
			block = cli.GetLatestBlock(conf.Host)
		} else if len(conf.BlockID) > 0 {
			blockID := flow.HexToID(conf.BlockID)
			block = cli.GetBlockByID(conf.Host, blockID)
		} else {
			block = cli.GetBlockByHeight(conf.Host, conf.BlockHeight)
		}
		printBlock(block)
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

func printBlock(block *flow.Block) {
	fmt.Println()
	fmt.Println("Block ID: ", block.ID)
	fmt.Println("Parent ID: ", block.ParentID)
	fmt.Println("Height: ", block.Height)
	fmt.Println("Timestamp: ", block.Timestamp)
	fmt.Println("Total Collections: ", len(block.CollectionGuarantees))
	for i, guarantee := range block.CollectionGuarantees {
		fmt.Printf("  Collection %d: %s\n", i, guarantee.CollectionID)
	}
	fmt.Println("Total Seals: ", len(block.Seals))
	fmt.Println()
}