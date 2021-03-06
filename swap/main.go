/**
*  @file
*  @copyright defined in go-seele/LICENSE
 */

package main

import (
	"log"
	"os"
	"sort"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "swap client"
	app.Usage = "interact with node swap contract"
	app.HideVersion = true

	app.Commands = []cli.Command{
		{
			Name:  "init",
			Usage: "deploy the contract in seele",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				feeFlag,
				nonceFlag,
			},
			Action: Deploy,
		},
		{
			Name:  "create",
			Usage: "create a new contract for htlc transaction on chain",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				toFlag,
				amountFlag,
				secretHashFlag,
				feeFlag,
				nonceFlag,
			},
			Action: Create,
		},
		{
			Name:  "participate",
			Usage: "create a new contract for htlc transaction on other chain",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				toFlag,
				amountFlag,
				secretHashFlag,
				feeFlag,
				nonceFlag,
			},
			Action: Participate,
		},
		{
			Name:  "withdraw",
			Usage: "withdraw seele from the contract",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				secretFlag,
				feeFlag,
				contractIdFlag,
				nonceFlag,
			},
			Action: Withdraw,
		},
		{
			Name:  "refund",
			Usage: "refund seele from the contract",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				feeFlag,
				contractIdFlag,
				nonceFlag,
			},
			Action: Refund,
		},
		{
			Name:  "getContractById",
			Usage: "get the transaction info from the contract by contract id",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				feeFlag,
				contractIdFlag,
				nonceFlag,
			},
			Action: GetContractInfo,
		},
		{
			Name:   "gensecret",
			Usage:  "generate secret and secret hash, secret hash is generated by sha256 ",
			Action: GenSecret,
		},
		{
			Name:  "unpack",
			Usage: "decode the result of getContractById command",
			Flags: []cli.Flag{
				addressFlag,
				hashFlag,
			},
			Action: Unpack,
		},
		{
			Name:  "getreceipt",
			Usage: "get receipt by transaction hash",
			Flags: []cli.Flag{
				addressFlag,
				hashFlag,
			},
			Action: GetReceipt,
		},
		{
			Name:  "getbalance",
			Usage: "get account balance",
			Flags: []cli.Flag{
				addressFlag,
				accountFlag,
			},
			Action: GetBalance,
		},
	}

	// sort commands and flags by name
	sort.Sort(cli.CommandsByName(app.Commands))
	sort.Sort(cli.FlagsByName(app.Flags))

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
