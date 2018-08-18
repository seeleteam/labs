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
	"github.com/seeleteam/labs/contract"
	"github.com/urfave/cli"
)

const (
	// DefaultNonce is the default value of nonce,when you are not set the nonce flag in client sendtx command by --nonce .
	DefaultNonce uint64 = 0

	dir          string = "./config/"
	deployfile   string = "deploy.json"
	createfile   string = "create.json"
	withdrawfile string = "withdraw.json"
	refundfile   string = "refund.json"

	hashKeyfile string = "hashkey.json"
)

// Deploy a contract in seele
func Deploy(c *cli.Context) error {
	bytecode, err := contract.GetContractByteCode()
	if err != nil {
		return fmt.Errorf("get deploy bytecode err: %s\n", err)
	}

	client, err := makeClient()
	if err != nil {
		return fmt.Errorf("can not connect to host:%s,err: %s\n", addressValue, err)
	}

	txdata, key, err := makeTransaction(client, "")
	if err != nil {
		return fmt.Errorf("make tx data err: %s\n", err)
	}

	tx, err := generateTx(key.PrivateKey, txdata.To, txdata.Amount, txdata.Fee, txdata.AccountNonce, bytecode)
	if err != nil {
		return err
	}
	var result bool
	err = client.Call(&result, "seele_addTx", tx)
	if err != nil || !result {
		return fmt.Errorf("failed to send transaction: %s\n", err)
	}

	fmt.Println("transaction sent successfully")
	data, err := json.MarshalIndent(tx, "", "\t")
	if err != nil {
		return fmt.Errorf("json mashalIndet err: %s\n", err)
	}

	fmt.Printf("%s\n", data)
	err = saveData(data, deployfile)
	if err != nil {
		return fmt.Errorf("save data to %s err: %s\n", deployfile, err)
	}

	return nil

}

// Create a contract in the deployed contract to swap
func Create(c *cli.Context) error {
	client, _, txdata, key, seele, err := getBaseInfo()
	if err != nil {
		return err
	}

	byteAddr, err := hexutil.HexToBytes(toValue)
	secret := make([]byte, 32)
	_, err = rand.Read(secret[:])
	if err != nil {
		return fmt.Errorf("rand secret error: %s\n", err)
	}

	secretHash := sha256Hash(secret[:])
	secretHex := hexutil.BytesToHex(secret)
	secretHashHex := hexutil.BytesToHex(secretHash[:])
	fmt.Println("secret hex:", secretHex)
	fmt.Println("secretHash hex:", secretHashHex)

	locktime := time.Now().Unix() + 48*60*3600
	fmt.Println("locktime:", locktime)

	bytecode, err := seele.NewContract(common.BytesToAddress(byteAddr), secretHash, big.NewInt(locktime))
	if err != nil {
		return fmt.Errorf("get create function byte code err: %s\n", err)
	}

	err = sendtx(client, key, txdata, bytecode, createfile)
	if err != nil {
		return err
	}

	keyInfo := make(map[string]string)
	keyInfo["secret"] = secretHex
	keyInfo["secretHash"] = secretHashHex

	data, err := json.MarshalIndent(keyInfo, "", "\t")
	if err != nil {
		return fmt.Errorf("key info json mashalIndet err: %s\n", err)
	}

	err = saveData(data, hashKeyfile)
	if err != nil {
		return fmt.Errorf("save data to %s err:%s\n", hashKeyfile, err)
	}

	return nil
}

// Withdraw seele for the contract with preimage
func Withdraw(c *cli.Context) error {
	client, _, txdata, key, seele, err := getBaseInfo()
	if err != nil {
		return err
	}

	contractIdStr, err := getContractId(client)
	if err != nil {
		return err
	}

	slice, err := hexutil.HexToBytes(contractIdStr)
	if err != nil {
		return err
	}

	contractId, err := getByte32(slice)
	if err != nil {
		return err
	}

	secret, err := getSecret()
	if err != nil {
		return err
	}

	secretSlice, err := hexutil.HexToBytes(secret)
	if err != nil {
		return err
	}

	secretData, err := getByte32(secretSlice)
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
	client, _, txdata, key, seele, err := getBaseInfo()
	if err != nil {
		return err
	}

	contractIdStr, err := getContractId(client)
	if err != nil {
		return err
	}

	slice, err := hexutil.HexToBytes(contractIdStr)
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
		return "", fmt.Errorf("read data file err:%s\n", err)
	}

	var result map[string]interface{}
	err = client.Call(&result, "txpool_getReceiptByTxHash", data["Hash"].(string))
	if err != nil {
		return "", fmt.Errorf("get receipt err:%s\n", err)
	}

	return result["contract"].(string), nil
}

func readData(file string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	buff, err := ioutil.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return nil, fmt.Errorf("read data err:%s\n", err)
	}

	err = json.Unmarshal(buff, &result)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal err:%s\n", err)
	}

	return result, nil
}

func saveData(data []byte, file string) error {
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("makedir err:%s\n", err)

	}

	err = ioutil.WriteFile(filepath.Join(dir, file), data, os.ModePerm)
	if err != nil {
		return fmt.Errorf("write file err:%s\n", err)
	}

	return nil
}

func makeTransaction(client *rpc.Client, to string) (*types.TransactionData, *keystore.Key, error) {
	pass, err := common.GetPassword()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get password %s\n", err)
	}

	key, err := keystore.GetKey(fromValue, pass)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid sender key file. it should be a private key: %s\n", err)
	}

	info := &types.TransactionData{}

	if len(to) > 0 {
		toAddr, err := common.HexToAddress(to)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid receiver address: %s", err)
		}
		info.To = toAddr
	}

	amount, ok := big.NewInt(0).SetString(amountValue, 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid amount value")
	}
	info.Amount = amount

	fee, ok := big.NewInt(0).SetString(feeValue, 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid fee value")
	}
	info.Fee = fee

	fromAddr := crypto.GetAddress(&key.PrivateKey.PublicKey)
	info.From = *fromAddr

	if client != nil {
		nonce, err := util.GetAccountNonce(client, *fromAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get the sender account nonce: %s", err)
		}

		if nonceValue == nonce || nonceValue == DefaultNonce {
			info.AccountNonce = nonce
		} else {
			if nonceValue < nonce {
				return nil, nil, fmt.Errorf("your nonce is: %d,current nonce is: %d,you must set your nonce greater than or equal to current nonce", nonceValue, nonce)
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
			return nil, fmt.Errorf("create a contract err:%s\n", err)
		}
	} else {
		switch to.Type() {
		case common.AddressTypeExternal:
			tx, err = types.NewTransaction(*fromAddr, to, amount, fee, nonce)
			if err != nil {
				return nil, fmt.Errorf("create a transaction err:%s\n", err)
			}
		case common.AddressTypeContract:
			tx, err = types.NewMessageTransaction(*fromAddr, to, amount, fee, nonce, payload)
			if err != nil {
				return nil, fmt.Errorf("create a message err:%s\n", err)
			}
		default:
			return nil, fmt.Errorf("unsupported address type: %d", to.Type())

		}
	}

	if err != nil {
		return nil, fmt.Errorf("create transaction err %s", err)
	}

	tx.Sign(from)

	return tx, nil
}

func getBaseInfo() (*rpc.Client, string, *types.TransactionData, *keystore.Key, *contract.SeeleContract, error) {
	client, err := makeClient()
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("can not connect to host:%s,err: %s\n", addressValue, err)
	}

	contractAddress, err := getContractAddress(client)
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("get contract address err: %s\n", err)
	}

	txdata, key, err := makeTransaction(client, contractAddress)
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("make tx data err:%s\n", err)
	}

	byteAddr, err := hexutil.HexToBytes(contractAddress)
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("contract address hex to byte err: %s\n", err)
	}

	seele, err := contract.NewSeeleContract(common.BytesToAddress(byteAddr))
	if err != nil {
		return nil, "", nil, nil, nil, fmt.Errorf("create SeeleContract type err: %s\n", err)
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
		return fmt.Errorf("failed to send transaction: %s\n", err)
	}

	fmt.Println("transaction sent successfully")
	data, err := json.MarshalIndent(tx, "", "\t")
	if err != nil {
		return fmt.Errorf("json mashalIndet err: %s\n", err)
	}

	fmt.Printf("%s\n", data)
	err = saveData(data, file)
	if err != nil {
		return fmt.Errorf("save data to %s err:%s\n", file, err)
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
		return "", fmt.Errorf("get receipt err:%s\n", err)
	}

	return result["result"].(string), nil
}

func getByte32(v []byte) ([32]byte, error) {
	if len(v) != 32 {
		return [32]byte{}, fmt.Errorf("the value is not 32 byte,len is:", len(v))
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
