package tools

import (
	"fmt"
	vm "github.com/ElrondNetwork/elrond-sdk-erdgo/data"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewElrondClient(t *testing.T) {
	ec := NewElrondClient("https://gateway.elrond.com")
	nonce, err := ec.GetLatestHyperblockNonce()

	fmt.Println(nonce)
	require.Nil(t, err)
}

func TestGetHyberblock(t *testing.T) {
	ec := NewElrondClient("https://devnet-gateway.elrond.com")
	hb, err := ec.GetHyperblockByNonce(1601343)

	if strings.Contains(string(hb.Transactions[0].Data), "createCrossChainTx") {
		fmt.Println("createCrossChainTx")
	}

	fmt.Println(hb)
	require.Nil(t, err)
}

func TestExecuteVmQuery(t *testing.T) {
	ec := NewElrondClient("https://gateway.elrond.com")

	hb, err := ec.ExecuteQuery(&vm.VmValueRequest{
		Address:    "erd1qqqqqqqqqqqqqpgqxwakt2g7u9atsnr03gqcgmhcv38pt7mkd94q6shuwt",
		FuncName:   "version",
		CallerAddr: "",
		CallValue:  "",
		Args:       nil,
	})

	fmt.Println(hb)
	require.Nil(t, err)
}

func TestElrondClient_GetTransactionByHash(t *testing.T) {
	ec := NewElrondClient("https://devnet-gateway.elrond.com")

	tx, err := ec.GetTransactionByHash("5e31b03bc90d8154854a37d86335e5a0f77ad602aaab6ac49d5e4056f2cb8cca")

	fmt.Println(tx)

	require.Nil(t, err)
}

func TestElrondClient_GetTransactionsForHyperblock(t *testing.T) {

	ec := NewElrondClient("https://devnet-gateway.elrond.com")

	res := ec.GetTransactionsForHyperblock(1601343)

	require.NotNil(t, res)
}
