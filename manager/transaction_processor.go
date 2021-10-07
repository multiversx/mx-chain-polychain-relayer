package manager

import (
	"math/big"

	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/polynetwork/poly/common"
)

type transactionProc struct {
	crossChainManagerContractAddress string
	elrondClient                     *tools.ElrondClient
}

func NewTransactionsProcessor(
	crossChainManagerContractAddress string,
	elrondClient *tools.ElrondClient,
) (*transactionProc, error) {
	return &transactionProc{
		crossChainManagerContractAddress: crossChainManagerContractAddress,
		elrondClient:                     elrondClient,
	}, nil
}

func (tp *transactionProc) computeCrossChainTransfer(hash string, nonce uint64) (*CrossTransfer, []byte, []byte, uint64, error) {
	tx, err := tp.elrondClient.GetTransactionByHash(hash)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	var rawEvent []byte
	if tx.Logs != nil {
		rawEvent = tx.Logs.Events[0].Data
	}

	txEvent := tp.NewTransactionEventFromBytes(rawEvent)
	index := big.NewInt(0)
	index.SetBytes(txEvent.crossChainTxId)

	return &CrossTransfer{
		txIndex: tools.EncodeBigInt(index),
		txId:    txEvent.sourceChainTxHash.ToArray(),
		value:   rawEvent,
		toChain: uint32(txEvent.toChainId),
		height:  nonce,
	}, txEvent.crossChainTxId, txEvent.assetHash, txEvent.toChainId, nil
}

type transactionEvent struct {
	sourceChainTxHash   common.Uint256
	crossChainTxId      []byte
	fromContractAddress []byte
	toChainId           uint64
	toContractAddress   []byte
	methodName          []byte
	assetHash           []byte
	destinationAddress  []byte
	amount              common.Uint256
}

func (tp *transactionProc) NewTransactionEventFromBytes(buffer []byte) *transactionEvent {
	sink := common.NewZeroCopySource(buffer)
	txEvent := &transactionEvent{}

	txEvent.sourceChainTxHash, _ = sink.NextHash()
	txEvent.crossChainTxId, _ = sink.NextVarBytes()
	txEvent.fromContractAddress, _ = sink.NextVarBytes()
	txEvent.toChainId, _ = sink.NextUint64()
	txEvent.toContractAddress, _ = sink.NextVarBytes()
	txEvent.methodName, _ = sink.NextVarBytes()

	args, _ := sink.NextVarBytes()
	sinkArgs := common.NewZeroCopySource(args)

	txEvent.assetHash, _ = sinkArgs.NextVarBytes()
	txEvent.destinationAddress, _ = sinkArgs.NextVarBytes()
	txEvent.amount, _ = sinkArgs.NextHash()

	return txEvent
}
