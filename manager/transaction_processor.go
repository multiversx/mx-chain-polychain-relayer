package manager

import (
	"encoding/hex"
	"fmt"

	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/ElrondNetwork/elrond-proxy-go/data"
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

func (tp *transactionProc) computeCrossChainTransfer(blockNonce uint64, tx *data.FullTransaction) (*CrossTransfer, error) {
	polyTxHash, txIndex, toChainID, err := tp.getNextPendingCrossChainTxData(tx)
	if err != nil {
		return nil, err
	}

	value, _ := tp.getPaymentForTxData(polyTxHash)
	/*if err != nil {
		return nil, err
	}*/
	value = tx.Data

	decodedTxHash, _ := hex.DecodeString(tx.Hash)

	return &CrossTransfer{
		txIndex: fmt.Sprintf("%d", txIndex),
		txId:    decodedTxHash,
		value:   value,
		toChain: toChainID,
		height:  blockNonce,
	}, nil
}

func (tp *transactionProc) getNextPendingCrossChainTxData(tx *data.FullTransaction) ([]byte, uint64, uint32, error) {
	// TODO add checks if tx correspond with the next pending cross tx
	_ = tx

	query := &data.VmValueRequest{
		Address:  tp.crossChainManagerContractAddress,
		FuncName: "getNextPendingCrossChainTx",
		CallerAddr: "erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th",
	}
	queryResponse, err := tp.elrondClient.ExecuteQuery(query)
	if err != nil {
		return nil, 0, 0, err
	}

	return getTxIndexAndToChainID(queryResponse.Data.ReturnData[0])
}

func (tp *transactionProc) getPaymentForTxData(polyTxHash []byte) ([]byte, error) {
	query := &data.VmValueRequest{
		Address:  tp.crossChainManagerContractAddress,
		FuncName: "getTxByHash",
		Args:     []string{hex.EncodeToString(polyTxHash)},
	}
	queryResponse, err := tp.elrondClient.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	return getTxValueFromData(queryResponse.Data.ReturnData[0])
}

func getTxIndexAndToChainID(dataBytes []byte) ([]byte, uint64, uint32, error) {
	sink := common.NewZeroCopySource(dataBytes)

	txHash, eof := sink.NextBytes(32)
	if eof {
		return nil, 0, 0, fmt.Errorf("cannot deserialize hash")
	}

	txNonce, eof := sink.NextUint64()
	if eof {
		return nil, 0, 0, fmt.Errorf("cannot deserialize id")
	}

	_, eof = sink.NextBytes(32)
	if eof {
		return nil, 0, 0, fmt.Errorf("cannot deserialize from_contract_address")
	}

	toChain, eof := sink.NextUint64()
	if eof {
		return nil, 0, 0, fmt.Errorf("cannot deserialize to_chain_id")
	}

	return txHash, txNonce, uint32(toChain), nil
}

func getTxValueFromData(dataBytes []byte) ([]byte, error) {
	sink := common.NewZeroCopySource(dataBytes)

	_, eof := sink.NextBytes(32)
	if eof {
		return nil, fmt.Errorf("cannot deserialize sender")
	}

	_, eof = sink.NextBytes(32)
	if eof {
		return nil, fmt.Errorf("cannot deserialize eof")
	}

	lengthNextParam, eof := sink.NextVarUint()
	if eof {
		return nil, fmt.Errorf("cannot deserialize lenght next parameter token_id")
	}

	_, eof = sink.NextBytes(lengthNextParam)
	if eof {
		return nil, fmt.Errorf("cannot deserialize token_id")
	}

	lengthNextParam, eof = sink.NextVarUint()
	if eof {
		return nil, fmt.Errorf("cannot deserialize lenght next parameter amount")
	}

	amount, eof := sink.NextBytes(lengthNextParam)
	if eof {
		return nil, fmt.Errorf("cannot deserialize amount")
	}

	return amount, nil
}
