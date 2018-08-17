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
			Action: RPCAction(GetInfoAction),
		},
		{
			Name:  "create",
			Usage: "create a new contract for htlc transaction",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				toFlag,
				amountFlag,
				feeFlag,
				nonceFlag,
			},
			Action: RPCAction(GetInfoAction),
		},
		{
			Name:  "withdraw",
			Usage: "get seele from the contract",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				toFlag,
				feeFlag,
				nonceFlag,
			},
			Action: RPCAction(GetInfoAction),
		},
		{
			Name:  "refund",
			Usage: "refund seele from the contract",
			Flags: []cli.Flag{
				addressFlag,
				fromFlag,
				toFlag,
				feeFlag,
				nonceFlag,
			},
			Action: RPCAction(GetInfoAction),
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
