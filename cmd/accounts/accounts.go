package accounts

import (
	"bytes"
	"fmt"
	"text/tabwriter"

	"github.com/onflow/flow-go-sdk"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:              "accounts",
	Short:            "Utilities to manage accounts",
	TraverseChildren: true,
}

// AccountResult represent result from all account commands
type AccountResult struct {
	*flow.Account
	showCode bool
}

// JSON convert result to JSON
func (r *AccountResult) JSON() interface{} {
	return r
}

// String convert result to string
func (r *AccountResult) String() string {
	var b bytes.Buffer
	writer := tabwriter.NewWriter(&b, 0, 8, 1, '\t', tabwriter.AlignRight)

	fmt.Fprintf(writer, "Address\t %s\n", r.Address)
	fmt.Fprintf(writer, "Balance\t %d\n", r.Balance)

	fmt.Fprintf(writer, "Keys\t %d\n", len(r.Keys))

	for i, key := range r.Keys {
		fmt.Fprintf(writer, "\nKey %d\tPublic Key\t %x\n", i, key.PublicKey.Encode())
		fmt.Fprintf(writer, "\tWeight\t %d\n", key.Weight)
		fmt.Fprintf(writer, "\tSignature Algorithm\t %s\n", key.SigAlgo)
		fmt.Fprintf(writer, "\tHash Algorithm\t %s\n", key.HashAlgo)
		fmt.Fprintf(writer, "\n")
	}

	if r.showCode {
		for name, code := range r.Contracts {
			fmt.Fprintf(writer, "Code '%s':\n", name)
			fmt.Fprintln(writer, string(code))
		}
	}

	writer.Flush()

	return b.String()
}

// Oneliner show result as one liner grep friendly
func (r *AccountResult) Oneliner() string {
	return fmt.Sprintf("Address: %s, Balance: %v, Keys: %s", r.Address, r.Balance, r.Keys[0].PublicKey)
}

func (r *AccountResult) ToConfig() string {
	// TODO: it would be good to have a --save-config flag and it would be added to config
	return ""
}