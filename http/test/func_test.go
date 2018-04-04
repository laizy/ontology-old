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

package test

import (
	"bytes"
	"math/big"
	"testing"
	"time"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	ctypes "github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/vm/neovm"
	vmtypes "github.com/ontio/ontology/vm/types"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/stretchr/testify/assert"
	"github.com/ontio/ontology/merkle"
	"fmt"
	"os"
)

func TestMerkleVerifier(t *testing.T) {
	type merkleProof struct {
		Type             string
		TransactionsRoot string
		BlockHeight      uint32
		CurBlockRoot     string
		CurBlockHeight   uint32
		TargetHashes     []string
	}
	proof := merkleProof{
		Type:             "MerkleProof",
		TransactionsRoot: "78c5d536ef07985b6cb46c43fefe08dbd08b74e7df529f1f918441a9244cc516",
		BlockHeight:      2,
		CurBlockRoot:     "caf9d0a933ae71309fc492a66c643e32cbe2d4d3206099bfd4999e4af87cbedf",
		CurBlockHeight:   352,
		TargetHashes: []string{
			"4c22b5e624c91fa114c257fe680ff7db248336ac679fe24dbc6d3f628bb11779",
			"7298a4203a41f0089d0c5aa12a225a595fa025608b4453e173fb9f0c37b283f2",
			"8f2993180bb4adfa2b3a5d62ba56929baf8ca44104b6a8f1606bec27fddb92f9",
			"a58a62c945996c5753b95f76f2f71a66bf8d9575db6c8b401c2be119f6e91d8f",
			"a9a7c8206601c3fb60152f97883a0be96e7965af9f4fb22191ce2154c213a6b1",
			"1243fb80abbee1fdb9ff4107e5da04733cabdabc83c5d52de63e3566b8516794",
			"ec0799f74b9100e632bd15ec0a3f0923fa01f28a9db6b9b9bef1c2eee0a59d5b",
			"fd3cbbfd7ae4ee053a6d0ad7ab68dbab1744fef1733f85e67c87bc1092276f32",
			"a3895ad9113d7862d7de84b6196359711f69262db2d62d1099c6ede2bfbc4146",
		},
	}

	verify := merkle.NewMerkleVerifier()
	var leaf_hash common.Uint256
	bys, _ := common.HexToBytes(proof.TransactionsRoot)
	leaf_hash.Deserialize(bytes.NewReader(bys))

	var root_hash common.Uint256
	bys, _ = common.HexToBytes(proof.CurBlockRoot)
	root_hash.Deserialize(bytes.NewReader(bys))

	var hashes []common.Uint256
	for _, v := range proof.TargetHashes {
		var hash common.Uint256
		bys, _ = common.HexToBytes(v)
		hash.Deserialize(bytes.NewReader(bys))
		hashes = append(hashes, hash)
	}
	res := verify.VerifyLeafHashInclusion(leaf_hash, proof.BlockHeight, hashes, root_hash, proof.CurBlockHeight+1)
	assert.Nil(t, res)

}

func TestCodeHash(t *testing.T) {
	code, _ := common.HexToBytes("")
	vmcode := vmtypes.VmCode{vmtypes.NEOVM, code}
	codehash := vmcode.AddressFromVmCode()
	fmt.Println(codehash.ToHexString())
	os.Exit(0)
}

func TestTxDeserialize(t *testing.T) {
	bys, _ := common.HexToBytes("")
	var txn types.Transaction
	if err := txn.Deserialize(bytes.NewReader(bys)); err != nil {
		fmt.Print("Deserialize Err:", err)
		os.Exit(0)
	}
	fmt.Printf("TxType:%x\n", txn.TxType)
	os.Exit(0)
}
func TestAddress(t *testing.T) {
	pubkey, _ := common.HexToBytes("120203a4e50edc1e59979442b83f327030a56bffd08c2de3e0a404cefb4ed2cc04ca3e")
	pk, err := keypair.DeserializePublicKey(pubkey)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	ui60 := types.AddressFromPubKey(pk)
	addr := common.ToHexString(ui60[:])
	fmt.Println(addr)
	fmt.Println(ui60.ToBase58())
}
func TestMultiPubKeysAddress(t *testing.T) {
	pubkey, _ := common.HexToBytes("120203a4e50edc1e59979442b83f327030a56bffd08c2de3e0a404cefb4ed2cc04ca3e")
	pk, err := keypair.DeserializePublicKey(pubkey)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	pubkey2, _ := common.HexToBytes("12020225c98cc5f82506fb9d01bad15a7be3da29c97a279bb6b55da1a3177483ab149b")
	pk2, err := keypair.DeserializePublicKey(pubkey2)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	ui60, _ := types.AddressFromMultiPubKeys([]keypair.PublicKey{pk, pk2}, 1)
	addr := common.ToHexString(ui60[:])
	fmt.Println(addr)
	fmt.Println(ui60.ToBase58())
}

func TestInvokefunction(t *testing.T) {
	var funcName string
	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	err := BuildSmartContractParamInter(builder, []interface{}{funcName, "", ""})
	if err != nil {
	}
	codeParams := builder.ToArray()
	tx := utils.NewInvokeTransaction(vmtypes.VmCode{
		VmType: vmtypes.Native,
		Code:   codeParams,
	})
	tx.Nonce = uint32(time.Now().Unix())

	acct := account.Open(account.WALLET_FILENAME, []byte("passwordtest"))
	acc, err := acct.GetDefaultAccount()
	if err != nil {
		fmt.Println("GetDefaultAccount error:", err)
		os.Exit(1)
	}
	hash := tx.Hash()
	sign, _ := signature.Sign(acc.PrivateKey, hash[:])
	tx.Sigs = append(tx.Sigs, &ctypes.Sig{
		PubKeys: []keypair.PublicKey{acc.PublicKey},
		M:       1,
		SigData: [][]byte{sign},
	})

	txbf := new(bytes.Buffer)
	if err := tx.Serialize(txbf); err != nil {
		fmt.Println("Serialize transaction error.")
		os.Exit(1)
	}
	common.ToHexString(txbf.Bytes())
}
func BuildSmartContractParamInter(builder *neovm.ParamsBuilder, smartContractParams []interface{}) error {
	for i := len(smartContractParams) - 1; i >= 0; i-- {
		switch v := smartContractParams[i].(type) {
		case bool:
			builder.EmitPushBool(v)
		case int:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int64:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case common.Fixed64:
			builder.EmitPushInteger(big.NewInt(int64(v.GetData())))
		case uint64:
			val := big.NewInt(0)
			builder.EmitPushInteger(val.SetUint64(uint64(v)))
		case string:
			builder.EmitPushByteArray([]byte(v))
		case *big.Int:
			builder.EmitPushInteger(v)
		case []byte:
			builder.EmitPushByteArray(v)
		case []interface{}:
			err := BuildSmartContractParamInter(builder, v)
			if err != nil {
				return err
			}
			builder.EmitPushInteger(big.NewInt(int64(len(v))))
			builder.Emit(neovm.PACK)
		default:
			return fmt.Errorf("unsupported param:%s", v)
		}
	}
	return nil
}
