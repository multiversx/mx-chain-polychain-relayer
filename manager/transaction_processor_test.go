package manager

import (
	"fmt"
	tools "github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestNewTransactionEventFromBytes(t *testing.T) {
	ec := tools.NewElrondClient("https://devnet-gateway.elrond.com")

	tx, err := ec.GetTransactionByHash("dd79517926062cf1a8c0a06bd54c1bdaa96e9e37d2f3cf554da49564f578da6a")

	tp := transactionProc{}
	txEvent := tp.NewTransactionEventFromBytes(tx.Logs.Events[0].Data)

	index := big.NewInt(0)
	index.SetBytes(txEvent.crossChainTxId)
	fmt.Println(tools.EncodeBigInt(index))

	fmt.Println(tx.Logs.Events[0].Identifier)

	require.Nil(t, err)
}

func Test_transactionProc_computeCrossChainTransfer(t *testing.T) {
	ec := tools.NewElrondClient("https://devnet-gateway.elrond.com")
	tp := transactionProc{elrondClient: ec}

	crossTx, crossChainTxId, assetHash, toChainID, err := tp.computeCrossChainTransfer("dd79517926062cf1a8c0a06bd54c1bdaa96e9e37d2f3cf554da49564f578da6a", 1612920)

	require.Nil(t, err)
	require.True(t, toChainID > 0)
	require.NotNil(t, assetHash)
	require.NotNil(t, crossTx)
	require.NotNil(t, crossChainTxId)
}
