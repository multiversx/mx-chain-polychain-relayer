package tools

import (
	"fmt"
	"testing"

	"github.com/ElrondNetwork/elrond-proxy-go/data"
	"github.com/stretchr/testify/require"
)

func TestNewElrondClient(t *testing.T) {
	ec := NewElrondClient("https://gateway.elrond.com")

	nonce, err := ec.GetLatestHyperblockNonce()

	fmt.Println(nonce)
	require.Nil(t, err)
}

func TestGetHyberblock(t *testing.T) {
	ec := NewElrondClient("https://gateway.elrond.com")

	hb, err := ec.GetHyperblockByNonce(1000)

	fmt.Println(hb)
	require.Nil(t, err)
}

func TestExecuteVmQuery(t *testing.T) {
	ec := NewElrondClient("https://gateway.elrond.com")

	hb, err := ec.ExecuteQuery(&data.VmValueRequest{
		Address:    "erd1qqqqqqqqqqqqqpgqxwakt2g7u9atsnr03gqcgmhcv38pt7mkd94q6shuwt",
		FuncName:   "version",
		CallerAddr: "",
		CallValue:  "",
		Args:       nil,
	})

	fmt.Println(hb)
	require.Nil(t, err)
}
