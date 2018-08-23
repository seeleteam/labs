/**
*  @file
*  @copyright defined in go-seele/LICENSE
 */

package main

import (
	"github.com/urfave/cli"
)

var (
	addressValue string
	addressFlag  = cli.StringFlag{
		Name:        "address, a",
		Value:       "127.0.0.1:8027",
		Usage:       "address for client to request",
		Destination: &addressValue,
	}

	fromValue string
	fromFlag  = cli.StringFlag{
		Name:        "from",
		Usage:       "key file of the sender",
		Destination: &fromValue,
	}

	toValue string
	toFlag  = cli.StringFlag{
		Name:        "to",
		Usage:       "to address",
		Destination: &toValue,
	}

	amountValue string
	amountFlag  = cli.StringFlag{
		Name:        "amount",
		Usage:       "amount value, unit is fan(default 0)",
		Destination: &amountValue,
	}

	feeValue string
	feeFlag  = cli.StringFlag{
		Name:        "fee",
		Usage:       "transaction fee",
		Destination: &feeValue,
	}

	nonceValue uint64
	nonceFlag  = cli.Uint64Flag{
		Name:        "nonce",
		Value:       0,
		Usage:       "transaction nonce",
		Destination: &nonceValue,
	}

	secretHashValue string
	secretHashFlag  = cli.StringFlag{
		Name:        "secrethash",
		Usage:       "hash of secret by sha256",
		Destination: &secretHashValue,
	}

	secretValue string
	secretFlag  = cli.StringFlag{
		Name:        "secret",
		Usage:       "value of secret, the preimage of secret hash",
		Destination: &secretValue,
	}

	contractIdValue string
	contractIdFlag  = cli.StringFlag{
		Name:        "contractId",
		Usage:       "contract id of the transaction id",
		Destination: &contractIdValue,
	}

	hashValue string
	hashFlag  = cli.StringFlag{
		Name:        "hash",
		Usage:       "hash of contract or tracsaction",
		Destination: &hashValue,
	}

	accountValue string
	accountFlag  = cli.StringFlag{
		Name:        "account",
		Usage:       "account address",
		Destination: &accountValue,
	}
)
