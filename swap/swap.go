package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/seeleteam/go-seele/cmd/util"
	"github.com/seeleteam/go-seele/common"
	"github.com/seeleteam/go-seele/common/hexutil"
	"github.com/seeleteam/go-seele/common/keystore"
	"github.com/seeleteam/go-seele/core/types"
	"github.com/seeleteam/go-seele/crypto"
	rpc "github.com/seeleteam/go-seele/rpc2"
	"github.com/seeleteam/go-seele/seele"
	"github.com/seeleteam/labs/abicommon"
	"github.com/seeleteam/labs/contract"
	"github.com/urfave/cli"
)

const (
	// DefaultNonce is the default value of nonce,when you are not set the nonce flag in client sendtx command by --nonce .
	DefaultNonce uint64 = 0

	defaultAmount string = "0"

	dir              string = "./config/"
	deployfile       string = "deploy.json"
	createfile       string = "create.json"
	participatefile  string = "participate.json"
	contractfile     string = "contract.json"
	withdrawfile     string = "withdraw.json"
	refundfile       string = "refund.json"
	hashKeyfile      string = "hashkey.json"
	contractInfofile string = "contractinfo.json"
)

type contractInfo struct {
	Sender    abicommon.Address
	Receiver  abicommon.Address
	Amount    *big.Int
	Hashlock  [32]byte
	Timelock  *big.Int
	Withdrawn bool
	Refunded  bool
	Preimage  [32]byte
}

type printInfo struct {
	Sender    abicommon.Address
	Receiver  abicommon.Address
	Amount    *big.Int
	Hashlock  string
	Timelock  *big.Int
	Withdrawn bool
	Refunded  bool
	Preimage  string
}

// Deploy a contract in seele
func Deploy(c *cli.Context) error {
	bytecode, err := contract.GetContractByteCode()
	if err != nil {
		return fmt.Errorf("Failed to get deploy bytecode err: %s\n", err)
	}

	client, err := makeClient()
	if err != nil {
		return fmt.Errorf("Failed to connect to host: %s,err: %s\n", addressValue, err)
	}

	txdata, key, err := makeTransaction(client, "", defaultAmount)
	if err != nil {
		return fmt.Errorf("Failed to make tx data err: %s\n", err)
	}

	tx, err := generateTx(key.PrivateKey, txdata.To, txdata.Amount, txdata.Fee, txdata.AccountNonce, bytecode)
	if err != nil {
		return err
	}
	var result bool
	err = client.Call(&result, "seele_addTx", tx)
	if err != nil || !result {
		return fmt.Errorf("Failed to send transaction: %s\n", err)
	}

	fmt.Println("transaction sent successfully")
	data, err := json.MarshalIndent(tx, "", "\t")
	if err != nil {
		return fmt.Errorf("Failed to marshal tx err: %s\n", err)
	}

	fmt.Printf("%s\n", data)
	err = saveData(data, deployfile)
	if err != nil {
		return fmt.Errorf("Failed to save data to %s err: %s\n", deployfile, err)
	}

	return nil
}

// Create a contract in the deployed contract to swap, time lock 48 hours
func Create(c *cli.Context) error {
	return create(48, createfile)
}

// Participate create a contract in the deployed contract to swap on other chain, time lock 24 hours
func Participate(c *cli.Context) error {
	return create(24, participatefile)
}

// Withdraw seele from the contract with preimage
func Withdraw(c *cli.Context) error {
	client, _, txdata, key, seele, err := getBaseInfo(defaultAmount)
	if err != nil {
		return err
	}

	secretSlice, err := hexutil.HexToBytes(secretValue)
	if err != nil {
		return fmt.Errorf("Failed to get secret from hex err: %s\n", err)
	}

	secretData, err := getByte32(secretSlice)
	if err != nil {
		return err
	}

	slice, err := hexutil.HexToBytes(contractIdValue)
	if err != nil {
		return err
	}

	contractId, err := getByte32(slice)
	if err != nil {
		return err
	}

	bytecode, err := seele.Withdraw(contractId, secretData)
	err = sendtx(client, key, txdata, bytecode, withdrawfile)
	if err != nil {
		return err
	}

	return nil
}

// Refund seele after the time lock
func Refund(c *cli.Context) error {
	client, _, txdata, key, seele, err := getBaseInfo(defaultAmount)
	if err != nil {
		return err
	}

	slice, err := hexutil.HexToBytes(contractIdValue)
	if err != nil {
		return err
	}

	contractId, err := getByte32(slice)
	if err != nil {
		return err
	}
	bytecode, err := seele.Refund(contractId)
	err = sendtx(client, key, txdata, bytecode, refundfile)
	if err != nil {
		return err
	}

	return nil
}

// GetContractInfo return Contract info by id
func GetContractInfo(c *cli.Context) error {
	client, _, txdata, key, seele, err := getBaseInfo(defaultAmount)
	if err != nil {
		return err
	}

	slice, err := hexutil.HexToBytes(contractIdValue)
	if err != nil {
		return err
	}

	contractId, err := getByte32(slice)
	if err != nil {
		return err
	}
	bytecode, err := seele.GetContractInfo(contractId)
	err = sendtx(client, key, txdata, bytecode, contractfile)
	if err != nil {
		return err
	}

	return nil
}

// GenSecret make a 32 bytes secret and secret hash
func GenSecret(c *cli.Context) error {
	secret := make([]byte, 32)
	_, err := rand.Read(secret[:])
	if err != nil {
		return fmt.Errorf("Failed to rand secret error: %s\n", err)
	}

	secretHash := sha256Hash(secret[:])
	secretHex := hexutil.BytesToHex(secret)
	secretHashHex := hexutil.BytesToHex(secretHash[:])
	fmt.Println("secret hex:", secretHex)
	fmt.Println("secretHash hex:", secretHashHex)

	keyInfo := make(map[string]string)
	keyInfo["secret"] = secretHex
	keyInfo["secretHash"] = secretHashHex

	data, err := json.MarshalIndent(keyInfo, "", "\t")
	if err != nil {
		return fmt.Errorf("Failed to marshal json keyinfo err: %s\n", err)
	}

	err = saveData(data, hashKeyfile)
	if err != nil {
		return fmt.Errorf("Failed to save data to %s err: %s\n", hashKeyfile, err)
	}

	return nil
}

// Unpack decode the result by contarct id
func Unpack(c *cli.Context) error {
	client, err := makeClient()
	if err != nil {
		return fmt.Errorf("Failed to connect to host: %s err: %s\n", addressValue, err)
	}

	var result map[string]interface{}
	err = client.Call(&result, "txpool_getReceiptByTxHash", hashValue)
	if err != nil {
		return fmt.Errorf("Failed to get receipt err: %s\n", err)
	}

	seele, err := contract.NewSeeleContract(common.EmptyAddress)
	if err != nil {
		return fmt.Errorf("Failed to create SeeleContract type err: %s\n", err)
	}

	data, err := hexutil.HexToBytes(result["result"].(string))
	if err != nil {
		return fmt.Errorf("Failed to change result-hex to bytes err: %s\n", err)
	}

	var info contractInfo
	err = seele.Unpack(&info, "getContract", data)
	if err != nil {
		return fmt.Errorf("Failed to unpack err: %s\n", err)
	}

	var print printInfo
	print.Amount = info.Amount
	print.Hashlock = hexutil.BytesToHex(info.Hashlock[:])
	print.Preimage = hexutil.BytesToHex(info.Preimage[:])
	print.Receiver = info.Receiver
	print.Refunded = info.Refunded
	print.Sender = info.Sender
	print.Timelock = info.Timelock
	print.Withdrawn = info.Withdrawn

	data, err = json.MarshalIndent(print, "", "\t")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)
	err = saveData(data, contractInfofile)
	if err != nil {
		return fmt.Errorf("Failed to create %s err: %s\n", contractInfofile, err)
	}

	return nil
}

// GetReceipt get transaction receipt by hash
func GetReceipt(c *cli.Context) error {
	client, err := makeClient()
	if err != nil {
		return fmt.Errorf("Failed to connect to host: %s err: %s\n", addressValue, err)
	}

	var result map[string]interface{}
	err = client.Call(&result, "txpool_getReceiptByTxHash", hashValue)
	if err != nil {
		return fmt.Errorf("Failed to get receipt err: %s\n", err)
	}

	data, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)

	return nil
}

// GetBalance returns the account balance
func GetBalance(c *cli.Context) error {
	account, err := MakeAddress(accountValue)
	if err != nil {
		return fmt.Errorf("Failed to convert account hex to address err: %s\n", err)
	}

	client, err := makeClient()
	if err != nil {
		return fmt.Errorf("Failed to connect to host: %s err: %s\n", addressValue, err)
	}

	var result seele.GetBalanceResponse
	err = client.Call(&result, "seele_getBalance", account)
	if err != nil {
		return fmt.Errorf("Failed to get balance err: %s\n", err)
	}

	data, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)

	return err
}

func MakeAddress(value string) (common.Address, error) {
	if value == "" {
		return common.EmptyAddress, nil
	} else {
		return common.HexToAddress(value)
	}
}

func create(hour int64, file string) error {
	client, _, txdata, key, seele, err := getBaseInfo(amountValue)
	if err != nil {
		return err
	}

	byteAddr, err := hexutil.HexToBytes(toValue)

	locktime := time.Now().Unix() + hour*3600
	fmt.Println("locktime:", locktime)

	secretHash, err := hexutil.HexToBytes(secretHashValue)
	if err != nil {
		return fmt.Errorf("Failed to convert secret-hex hash to bytes err: %s\n", err)
	}

	secretHashbyte32, err := getByte32(secretHash)
	if err != nil {
		return err
	}

	bytecode, err := seele.NewContract(common.BytesToAddress(byteAddr), secretHashbyte32, big.NewInt(locktime))
	if err != nil {
		return fmt.Errorf("Failed to get create function byte code err: %s\n", err)
	}

	err = sendtx(client, key, txdata, bytecode, file)
	if err != nil {
		return err
	}

	return nil
}

func makeClient() (*rpc.Client, error) {
	return rpc.DialTCP(context.Background(), addressValue)
}

func sha256Hash(x []byte) [32]byte {
	h := sha256.Sum256(x)
	return [32]byte(h)
}

func getContractAddress(client *rpc.Client) (string, error) {
	data, err := readData(deployfile)
	if err != nil {
		return "", fmt.Errorf("Failed to read data file err: %s\n", err)
	}

	var result map[string]interface{}
	err = client.Call(&result, "txpool_getReceiptByTxHash", data["Hash"].(string))
	if err != nil {
		return "", fmt.Errorf("Failed to get receipt err: %s\n", err)
	}

	return result["contract"].(string), nil
}

func readData(file string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	buff, err := ioutil.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return nil, fmt.Errorf("Failed to read data err: %s\n", err)
	}

	err = json.Unmarshal(buff, &result)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal json err: %s\n", err)
	}

	return result, nil
}

func saveData(data []byte, file string) error {
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to makedir err: %s\n", err)

	}

	err = ioutil.WriteFile(filepath.Join(dir, file), data, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to write file err: %s\n", err)
	}

	return nil
}

func makeTransaction(client *rpc.Client, to string, amount string) (*types.TransactionData, *keystore.Key, error) {
	pass, err := common.GetPassword()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get password err: %s\n", err)
	}

	key, err := keystore.GetKey(fromValue, pass)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get sender key file. it should be a private key: %s\n", err)
	}

	info := &types.TransactionData{}

	if len(to) > 0 {
		toAddr, err := common.HexToAddress(to)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to get receiver address err: %s\n", err)
		}
		info.To = toAddr
	}

	amountNum, ok := big.NewInt(0).SetString(amount, 10)
	if !ok {
		return nil, nil, fmt.Errorf("Failed to get amount value, invalid\n")
	}
	info.Amount = amountNum

	fee, ok := big.NewInt(0).SetString(feeValue, 10)
	if !ok {
		return nil, nil, fmt.Errorf("Failed to get fee value, invalid\n")
	}
	info.Fee = fee

	fromAddr := crypto.GetAddress(&key.PrivateKey.PublicKey)
	info.From = *fromAddr

	if client != nil {
		nonce, err := util.GetAccountNonce(client, *fromAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to get the sender account nonce: %s\n", err)
		}

		if nonceValue == nonce || nonceValue == DefaultNonce {
			info.AccountNonce = nonce
		} else {
			if nonceValue < nonce {
				return nil, nil, fmt.Errorf("Invalid nonce: %d, current nonce is: %d, you must set your nonce greater than or equal to current nonce", nonceValue, nonce)
			}
			info.AccountNonce = nonceValue
		}

		fmt.Printf("account %s current nonce: %d, sending nonce: %d\n", fromAddr.ToHex(), nonce, info.AccountNonce)
	} else {
		info.AccountNonce = nonceValue
	}

	return info, key, nil
}

func generateTx(from *ecdsa.PrivateKey, to common.Address, amount *big.Int, fee *big.Int, nonce uint64, payload []byte) (*types.Transaction, error) {
	fromAddr := crypto.GetAddress(&from.PublicKey)

	var tx *types.Transaction
	var err error
	if to.IsEmpty() {
		tx, err = types.NewContractTransaction(*fromAddr, amount, fee, nonce, payload)
		if err != nil {
			return nil, fmt.Errorf("Failed to create a contract err: %s\n", err)
		}
	} else {
		switch to.Type() {
		case common.AddressTypeExternal:
			tx, err = types.NewTransaction(*fromAddr, to, amount, fee, nonce)
			if err != nil {
				return nil, fmt.Errorf("Failed to create a transaction err: %s\n", err)
			}
		case common.AddressTypeContract:
			tx, err = types.NewMessageTransaction(*fromAddr, to, amount, fee, nonce, payload)
			if err != nil {
				return nil, fmt.Errorf("Failed to create a message err: %s\n", err)
			}
		default:
			return nil, fmt.Errorf("unsupported address type: %d\n", to.Type())

		}
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to create transaction err: %s\n", err)
	}

	tx.Sign(from)

	return tx, nil
}

func getBaseInfo(amount string) (*rpc.Client, string, *types.TransactionData, *keystore.Key, *contract.SeeleContract, error) {
	client, err := makeClient()
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("Failed to connect to host: %s  err: %s\n", addressValue, err)
	}

	contractAddress, err := getContractAddress(client)
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("Failed to get contract address err: %s\n", err)
	}

	txdata, key, err := makeTransaction(client, contractAddress, amount)
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("Failed to make tx data err: %s\n", err)
	}

	byteAddr, err := hexutil.HexToBytes(contractAddress)
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("Failed to convert contract address hex to bytes err: %s\n", err)
	}

	seele, err := contract.NewSeeleContract(common.BytesToAddress(byteAddr))
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("Failed to create SeeleContract type err: %s\n", err)
	}

	return client, contractAddress, txdata, key, seele, nil
}

func sendtx(client *rpc.Client, key *keystore.Key, txdata *types.TransactionData, bytecode []byte, file string) error {
	tx, err := generateTx(key.PrivateKey, txdata.To, txdata.Amount, txdata.Fee, txdata.AccountNonce, bytecode)
	if err != nil {
		return err
	}
	var result bool
	err = client.Call(&result, "seele_addTx", tx)
	if err != nil || !result {
		return fmt.Errorf("Failed to send transaction: %s\n", err)
	}

	fmt.Println("transaction sent successfully")
	data, err := json.MarshalIndent(tx, "", "\t")
	if err != nil {
		return fmt.Errorf("Failed to marshal json err: %s\n", err)
	}

	fmt.Printf("%s\n", data)
	err = saveData(data, file)
	if err != nil {
		return fmt.Errorf("Failed to save data to %s err: %s\n", file, err)
	}

	return nil
}

func getContractId(client *rpc.Client) (string, error) {
	data, err := readData(createfile)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	err = client.Call(&result, "txpool_getReceiptByTxHash", data["Hash"].(string))
	if err != nil {
		return "", fmt.Errorf("Failed to get receipt err: %s\n", err)
	}

	return result["result"].(string), nil
}

func getByte32(v []byte) ([32]byte, error) {
	if len(v) != 32 {
		return [32]byte{}, fmt.Errorf("The length %d is invalid, should be 32\n", len(v))
	}

	var data [32]byte
	for i := 0; i < 32; i++ {
		data[i] = v[i]
	}
	return data, nil
}

func getSecret() (string, error) {
	data, err := readData(hashKeyfile)
	if err != nil {
		return "", err
	}

	return data["secret"].(string), nil
}
