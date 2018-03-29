/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"os"
	"runtime"
	"sort"
	"time"
	"math/big"
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/config"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/genesis"
	"github.com/ontio/ontology/core/ledger"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/events"
	"github.com/ontio/ontology/smartcontract/service/native/states"
	vmtypes "github.com/ontio/ontology/vm/types"
	"github.com/ontio/ontology-crypto/keypair"
)

const (
	DefaultMultiCoreNum = 4
)

func init() {
	log.Init(log.PATH, log.Stdout)
	// Todo: If the actor bus uses a different log lib, remove it

	var coreNum int
	if config.Parameters.MultiCoreNum > DefaultMultiCoreNum {
		coreNum = int(config.Parameters.MultiCoreNum)
	} else {
		coreNum = DefaultMultiCoreNum
	}
	log.Debug("The Core number is ", coreNum)
	runtime.GOMAXPROCS(coreNum)
}

func main() {
	var acct *account.Account
	var err error
	log.Trace("Node version: ", config.Version)

	// Set default signature scheme
	config.Parameters.SignatureScheme = "SHA256withECDSA"
	err = signature.SetDefaultScheme(config.Parameters.SignatureScheme)
	if err != nil {
		log.Warn("Config error: ", err)
	}

	log.Info("0. Open the account")
	client := account.GetClient()
	if client == nil {
		log.Fatal("Can't get local account.")
		os.Exit(1)
	}
	acct, err = client.GetDefaultAccount()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	buf := keypair.SerializePublicKey(acct.PublicKey)
	config.Parameters.Bookkeepers = []string{hex.EncodeToString(buf)}
	log.Debug("The Node's PublicKey ", acct.PublicKey)

	defBookkeepers, err := client.GetBookkeepers()
	sort.Sort(keypair.NewPublicList(defBookkeepers))
	if err != nil {
		log.Fatalf("GetBookkeepers error:%s", err)
		os.Exit(1)
	}

	//Init event hub
	events.Init()

	log.Info("1. Loading the Ledger")
	ledger.DefLedger, err = ledger.NewLedger()
	if err != nil {
		log.Fatalf("NewLedger error %s", err)
		os.Exit(1)
	}
	err = ledger.DefLedger.Init(defBookkeepers)
	if err != nil {
		log.Fatalf("DefLedger.Init error %s", err)
		os.Exit(1)
	}

	TxGen(acct)

}

func GenAccounts(num int) []*account.Account {
	var accounts []*account.Account
	for i := 0; i < num; i++ {
		acc := account.NewAccount()
		accounts = append(accounts, acc)
	}
	return accounts
}

func signTransaction(signer *account.Account, tx *types.Transaction) error {
	hash := tx.Hash()
	sign, _ := signature.Sign(signer.PrivateKey, hash[:])
	tx.Sigs = append(tx.Sigs, &types.Sig{
		PubKeys: []keypair.PublicKey{signer.PublicKey},
		M:       1,
		SigData: [][]byte{sign},
	})
	return nil
}

func TxGen(issuer *account.Account) {
	// 生成1000个账户
	// 构造交易向这些账户转一个ont，每个区块10笔交易
	N := 1000 // 要小于max uint16
	accounts := GenAccounts(N)

	tsTx := make([]*types.Transaction, N)
	for i := 0; i < len(tsTx); i++ {
		tsTx[i] = NewTransferTransaction(genesis.OntContractAddress, issuer.Address, accounts[i].Address, 1)
		if err := signTransaction(issuer, tsTx[i]); err != nil {
			fmt.Println("signTransaction error:", err)
			os.Exit(1)
		}
	}

	ont := int64(genesis.OntRegisterAmount)
	ong := int64(0)
	ongappove := int64(0)
	for i := 0; i < 10; i++ {
		block, _ := makeBlock(issuer, tsTx[i*100:(i+1)*100])
		err := ledger.DefLedger.AddBlock(block)
		if err != nil {
			fmt.Println("persist block error", err)
			return
		}

		state := getState(issuer.Address)
		ongappove += ont * 80
		ont -= 100

		checkEq(state["ont"], ont)
		checkEq(state["ong"], ong)
		checkEq(state["ongAppove"], ongappove)

		fmt.Println(state)
	}

	// 账户0 转账给自己，区块高度为11，预计ong approve 为 (11-1)*80
	{

		tx := NewTransferTransaction(genesis.OntContractAddress, accounts[0].Address, accounts[0].Address, 1)
		if err := signTransaction(accounts[0], tx); err != nil {
			fmt.Println("signTransaction error:", err)
			os.Exit(1)
		}
		block, _ := makeBlock(issuer, []*types.Transaction{tx})
		err := ledger.DefLedger.AddBlock(block)
		if err != nil {
			fmt.Println("persist block error", err)
			return
		}

		state := getState(accounts[0].Address)
		checkEq(state["ont"], 1)
		checkEq(state["ong"], 0)
		ongapp := int64((11 - 1) * 80)
		checkEq(state["ongAppove"], ongapp)
		fmt.Println(state)
	}

	// step 3 : claim ong
	// 账户0 调用transferFrom自己，区块高度为12，预计ong为 (11-1)*80, ong appove 回到0
	{
		ongapp := int64((11 - 1) * 80)

		tx := NewOngTransferFromTransaction(genesis.OntContractAddress, accounts[0].Address, accounts[0].Address, ongapp)
		if err := signTransaction(accounts[0], tx); err != nil {
			fmt.Println("signTransaction error:", err)
			os.Exit(1)
		}
		block, _ := makeBlock(issuer, []*types.Transaction{tx})
		err := ledger.DefLedger.AddBlock(block)
		if err != nil {
			fmt.Println("persist block error", err)
			return
		}

		state := getState(accounts[0].Address)
		checkEq(state["ont"], 1)
		checkEq(state["ong"], ongapp)
		checkEq(state["ongAppove"], 0)
		fmt.Println(state)
	}

	// step4 ong 转账
	// 账户0 将400 ong 转给 issuer， 预计 账户0 ong为400， issuer 的ong为400
	{
		issuerState := getState(issuer.Address)
		tx := NewTransferTransaction(genesis.OngContractAddress, accounts[0].Address, issuer.Address, 400)
		if err := signTransaction(accounts[0], tx); err != nil {
			fmt.Println("signTransaction error:", err)
			os.Exit(1)
		}
		block, _ := makeBlock(issuer, []*types.Transaction{tx})
		err := ledger.DefLedger.AddBlock(block)
		if err != nil {
			fmt.Println("persist block error", err)
			return
		}

		state := getState(accounts[0].Address)
		checkEq(state["ont"], 1)
		checkEq(state["ong"], 400)
		checkEq(state["ongAppove"], 0)
		fmt.Println(state)

		state = getState(issuer.Address)
		checkEq(state["ont"], issuerState["ont"])
		checkEq(state["ong"], 400)
		checkEq(state["ongAppove"], issuerState["ongAppove"])
		fmt.Println(state)
	}

}

func checkEq(a, b int64) {
	if a != b {
		panic(fmt.Sprintf("not equal. a %s, b %s", a, b))
	}
}

func getState(addr common.Address) map[string]int64 {
	ont := new(big.Int)
	ong := new(big.Int)
	appove := new(big.Int)

	ontBalance, _ := ledger.DefLedger.GetStorageItem(genesis.OntContractAddress, addr[:])
	if ontBalance != nil {
		ont.SetBytes(ontBalance)
	}
	ongBalance, _ := ledger.DefLedger.GetStorageItem(genesis.OngContractAddress, addr[:])
	if ongBalance != nil {
		ong.SetBytes(ongBalance)
	}

	appoveKey := append(genesis.OntContractAddress[:], addr[:]...)
	ongappove, _ := ledger.DefLedger.GetStorageItem(genesis.OngContractAddress, appoveKey[:])
	if ongappove != nil {
		appove.SetBytes(ongappove)
	}

	rsp := make(map[string]int64)
	rsp["ont"] = ont.Int64()
	rsp["ong"] = ong.Int64()
	rsp["ongAppove"] = appove.Int64()

	return rsp
}

func makeBlock(acc *account.Account, txs []*types.Transaction) (*types.Block, error) {
	nextBookkeeper, err := types.AddressFromBookkeepers([]keypair.PublicKey{acc.PublicKey})
	if err != nil {
		return nil, fmt.Errorf("GetBookkeeperAddress error:%s", err)
	}
	prevHash := ledger.DefLedger.GetCurrentBlockHash()
	height := ledger.DefLedger.GetCurrentBlockHeight()

	nonce := uint64(height)
	txBookkeeping := createBookkeepingTransaction(acc)

	transactions := make([]*types.Transaction, 0, len(txs)+1)
	transactions = append(transactions, txBookkeeping)
	transactions = append(transactions, txs...)

	txHash := []common.Uint256{}
	for _, t := range transactions {
		txHash = append(txHash, t.Hash())
	}
	txRoot, err := common.ComputeRoot(txHash)
	if err != nil {
		return nil, fmt.Errorf("ComputeRoot error:%s", err)
	}

	blockRoot := ledger.DefLedger.GetBlockRootWithNewTxRoot(txRoot)
	header := &types.Header{
		Version:          0,
		PrevBlockHash:    prevHash,
		TransactionsRoot: txRoot,
		BlockRoot:        blockRoot,
		Timestamp:        uint32(time.Now().Unix()) + height,
		Height:           height + 1,
		ConsensusData:    nonce,
		NextBookkeeper:   nextBookkeeper,
	}
	block := &types.Block{
		Header:       header,
		Transactions: transactions,
	}

	blockHash := block.Hash()

	sig, err := signature.Sign(acc.PrivKey(), blockHash[:])
	if err != nil {
		return nil, fmt.Errorf("[Signature],Sign error:%s.", err)
	}

	block.Header.Bookkeepers = []keypair.PublicKey{acc.PublicKey}
	block.Header.SigData = [][]byte{sig}
	return block, nil
}

func createBookkeepingTransaction(acc *account.Account) *types.Transaction {
	bookKeepingPayload := &payload.BookKeeping{
		Nonce: uint64(time.Now().UnixNano()),
	}
	tx := &types.Transaction{
		TxType:     types.BookKeeping,
		Payload:    bookKeepingPayload,
		Attributes: []*types.TxAttribute{},
	}
	txHash := tx.Hash()

	s, err := signature.Sign(acc.PrivateKey, txHash[:])
	if err != nil {
		return nil
	}
	sig := &types.Sig{
		PubKeys: []keypair.PublicKey{acc.PublicKey},
		M:       1,
		SigData: [][]byte{s},
	}
	tx.Sigs = []*types.Sig{sig}
	return tx
}

func NewOngTransferFromTransaction(from, to, sender common.Address, value int64) *types.Transaction {
	sts := &states.TransferFrom{
		From:   from,
		To:     to,
		Sender: sender,
		Value:  big.NewInt(value),
	}

	bf := new(bytes.Buffer)

	if err := sts.Serialize(bf); err != nil {
		fmt.Println("Serialize transfers struct error.")
		os.Exit(1)
	}

	cont := &states.Contract{
		Address: genesis.OngContractAddress,
		Method:  "transferFrom",
		Args:    bf.Bytes(),
	}

	ff := new(bytes.Buffer)
	if err := cont.Serialize(ff); err != nil {
		fmt.Println("Serialize contract struct error.")
		os.Exit(1)
	}

	tx := utils.NewInvokeTransaction(vmtypes.VmCode{
		VmType: vmtypes.Native,
		Code:   ff.Bytes(),
	})

	tx.Nonce = uint32(time.Now().Unix())

	return tx
}

func NewTransferTransaction(asset common.Address, from, to common.Address, value int64) *types.Transaction {
	var sts []*states.State
	sts = append(sts, &states.State{
		From:  from,
		To:    to,
		Value: big.NewInt(value),
	})
	transfers := new(states.Transfers)
	transfers.States = sts

	bf := new(bytes.Buffer)

	if err := transfers.Serialize(bf); err != nil {
		fmt.Println("Serialize transfers struct error.")
		os.Exit(1)
	}

	cont := &states.Contract{
		Address: asset,
		Method:  "transfer",
		Args:    bf.Bytes(),
	}

	ff := new(bytes.Buffer)
	if err := cont.Serialize(ff); err != nil {
		fmt.Println("Serialize contract struct error.")
		os.Exit(1)
	}

	tx := utils.NewInvokeTransaction(vmtypes.VmCode{
		VmType: vmtypes.Native,
		Code:   ff.Bytes(),
	})

	tx.Nonce = uint32(time.Now().Unix())

	return tx
}
