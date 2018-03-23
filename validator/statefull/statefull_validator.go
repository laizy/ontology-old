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

package statefull

import (
	"reflect"

	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/ledger"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/errors"
	"github.com/ontio/ontology/validator/db"
	vatypes "github.com/ontio/ontology/validator/types"
	"github.com/ontio/ontology-eventbus/actor"
	ledgerActor "github.com/Ontology/core/ledger/actor"
)

type Validator interface {
	Register(poolId *actor.PID)
	UnRegister(poolId *actor.PID)
	VerifyType() vatypes.VerifyType
}

type validator struct {
	pid       *actor.PID
	id        string
	bestBlock db.BestBlock
	db        db.TransactionProvider
	knownHeight  uint32
	ledger *actor.PID
}

func NewValidator(id string, ledger *actor.PID, genesisBlock *types.Block) (Validator, error) {
	store, err := db.NewStore("Chain/statefull.db")

	header, err := store.GetGenesisHeader()
	// fresh db
	if err != nil {
		err := store.PersistBlock(genesisBlock)
		if err != nil {
			return nil, err
		}
	} else if header.Hash() != genesisBlock.Hash() {
		return nil, fmt.Errorf("mismatched ledger! persisted genesis block hash %x, given %x ",
			header.Hash(), genesisBlock.Hash())
	}

	validator := &validator{id: id, ledger:ledger, db: store}
	props := actor.FromProducer(func() actor.Actor {
		return validator
	})

	pid, err := actor.SpawnNamed(props, id)
	if err != nil {
		return nil, err
	}

	validator.pid = pid
	return validator, err
}

func (self *validator) Receive(context actor.Context) {
	switch msg := context.Message().(type) {
	case *actor.Started:
		log.Info("statefull-validator started and be ready to receive txn")
	case *actor.Stopping:
		log.Info("statefull-validator stopping")
	case *actor.Restarting:
		log.Info("statefull-validator Restarting")
	case *vatypes.CheckTx:
		log.Infof("statefull-validator receive tx %x", msg.Tx.Hash())
		sender := context.Sender()
		height := ledger.DefLedger.GetCurrentBlockHeight()

		errCode := errors.ErrNoError
		hash := msg.Tx.Hash()

		exist, err := ledger.DefLedger.IsContainTransaction(hash)
		if err != nil {
			log.Warn("query db error:", err)
			errCode = errors.ErrUnknown
		} else if exist {
			errCode = errors.ErrDuplicatedTx
		}

		response := &vatypes.CheckResponse{
			WorkerId: msg.WorkerId,
			Type:     self.VerifyType(),
			Hash:     msg.Tx.Hash(),
			Height:   height,
			ErrCode:  errCode,
		}

		sender.Tell(response)
	case *vatypes.UnRegisterAck:
		context.Self().Stop()
	case *types.Block:
		self.knownHeight = msg.Header.Height
		bestBlock, _ := self.db.GetBestBlock()

		if bestBlock.Height+1 < msg.Header.Height {
			self.ledger.Request(ledgerActor.GetBlockByHeightReq{ Height: bestBlock.Height + 1}, self.pid)
		} else if bestBlock.Height+1 == msg.Header.Height {
			err := self.db.PersistBlock(msg)
			if err != nil {
				log.Errorf("statefull-validator: persist block error", err)
				return
			}
		}

	case *ledgerActor.GetBlockByHeightRsp:
		if msg.Error != nil {
			return
		}

		block := msg.Block
		bestBlock, _ := self.db.GetBestBlock()
		if bestBlock.Height+1 < block.Header.Height {
			self.ledger.Request(ledgerActor.GetBlockByHeightReq{ Height: bestBlock.Height + 1}, self.pid)
		} else if bestBlock.Height+1 == block.Header.Height {
			err := self.db.PersistBlock(block)
			if err != nil {
				log.Errorf("statefull-validator: persist block error", err)
				return
			}
			if block.Header.Height < self.knownHeight {
				self.ledger.Request(ledgerActor.GetBlockByHeightReq{ Height: bestBlock.Height + 1}, self.pid)
			}
		}

	default:
		log.Info("statefull-validator: unknown msg ", msg, "type", reflect.TypeOf(msg))
	}

}

func (self *validator) VerifyType() vatypes.VerifyType {
	return vatypes.Statefull
}

func (self *validator) Register(poolId *actor.PID) {
	poolId.Tell(&vatypes.RegisterValidator{
		Sender: self.pid,
		Type:   self.VerifyType(),
		Id:     self.id,
	})
}

func (self *validator) UnRegister(poolId *actor.PID) {
	poolId.Tell(&vatypes.UnRegisterValidator{
		Id: self.id,
	})
}
