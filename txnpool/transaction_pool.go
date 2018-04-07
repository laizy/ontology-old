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

package txnpool

import (
	"errors"

	"github.com/ontio/ontology/common"
	txpc "github.com/ontio/ontology/txnpool/common"
	"github.com/ontio/ontology/core/types"
	vt "github.com/ontio/ontology/validator/types"
	"github.com/ontio/ontology/common/log"
	"time"
)

var TooManyPendingTxError = errors.New("too many pending tx")
var DuplicateTxError = errors.New("duplicated tx")
var NotEnoughValidatorError = errors.New("not enough validator")

type PoolConfig struct {
	MaxTxInBlock int
	MaxPendingTx int
	MaxCheckingTx int
}

type TxEntry struct {
	Tx    *types.Transaction // transaction which has been verified
	Fee   common.Fixed64     // Total fee per transaction
	TimeStamp int64
	VerifyHeight uint32
	PassStateless bool
	PassStateful bool
}

type TxPool struct{
	config PoolConfig

	txs map[common.Uint256]*TxEntry //
	passed []*TxEntry
	checking []*TxEntry
	pending []*TxEntry
	//passed map[common.Uint256]*txpc.TXEntry // Transactions which have been verified
	//waiting map[common.Uint256]*txpc.TXEntry // Transactions which have scheduled and wait for response
	//pending []*types.Transaction   // Transactions which have not been scheduled to verify yet
	validators [2]struct {              // 1: stateless, 2: stateful
		cursor int
		validator []*vt.RegisterValidator
	}
}

func (self *TxPool) haveEnoughValidator() bool {
	return len(self.validators[0].validator) > 0 && len(self.validators[1].validator) > 0
}

func (self *TxPool)verifyTx(entry *TxEntry) {
	if entry.PassStateless == false {
		//self.validators[0].validator[0].Sender
		panic("unimplemented")
	}
	panic("unimplemented")
}

func (self *TxPool) handle

func (self *TxPool) handleVerifyTransaction(tx *types.Transaction) error {
	if self.haveEnoughValidator() == false {
		return NotEnoughValidatorError
	}
	if len(self.pending) >= self.config.MaxPendingTx {
		return TooManyPendingTxError
	}
	if self.txs[tx.Hash()] != nil {
		return DuplicateTxError
	}
	entry := &TxEntry{
		Tx : tx,
		Fee: tx.GetTotalFee(),
	}

	self.txs[tx.Hash()] = entry
	if len(self.checking) < self.config.MaxCheckingTx {
		entry.TimeStamp = time.Now().Unix()
		self.checking = append(self.checking, entry)
		self.verifyTx(entry)
	} else {
		self.pending = append(self.pending, entry)
	}

	return nil
}

func isValidationExpired(entry *TxEntry, height uint32) bool {
	return entry.VerifyHeight < height
}

func (self *TxPool) GetVerifiedTxs(byCount bool, height uint32) []*TxEntry {
	i, j := 0, len(self.passed) - 1
	for i <= j {
		if isValidationExpired(self.passed[i], height) {
			self.passed[i].PassStateful = false
			self.passed[i], self.passed[j] = self.passed[j], self.passed[i]
			j -= 1
		} else {
			i+= 1
		}
	}

	// now passed[j+1:] is expired
	log.Infof("transaction pool: exipred %d transactions", len(self.passed)-j-1)
	var expired []*TxEntry
	expired = append(expired, self.passed[j+1:]...)
	self.pending = append(expired, self.pending...)
	self.passed = self.passed[:j+1]

	count := self.config.MaxTxInBlock
	if len(self.passed) < count || !byCount {
		count = len(self.passed)
	}

	txList := make([]*TxEntry, count)
	copy(txList, self.passed)

	return txList
}


