package manager

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/polynetwork/poly/common"
)

func TestPendingTx(t *testing.T) {
	myTx := "25a4fa887af0bb300e21a4bf8c6a7101a17c2039af36ae9b33b32ee962e64039000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e10d66756e6374696f6e5f6e616d650308617267756d656e74030201010164"
	decoded, _ := hex.DecodeString(myTx)

	sink := common.NewZeroCopySource(decoded)

	txIndex, eof := sink.NextBytes(32)
	fmt.Println(hex.EncodeToString(txIndex))
	fmt.Println(eof)

	value, eof := sink.NextUint64()
	fmt.Println(value)
	fmt.Println(eof)

	add, eof := sink.NextBytes(32)
	fmt.Println(add)
	fmt.Println(eof)

	toChain, eof := sink.NextUint64()
	fmt.Println(toChain)
	fmt.Println(eof)

	toContractAddress, eof := sink.NextBytes(32)
	fmt.Println(hex.EncodeToString(toContractAddress))
	fmt.Println(eof)
}

func TestEsdtPayment(t *testing.T) {
	esdtPayment := "0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e100000000000000000000000000000000000000000000000000000000000000000b5772617070656445676c6403989680"
	decoded, _ := hex.DecodeString(esdtPayment)

	sink := common.NewZeroCopySource(decoded)

	sender, _ := sink.NextBytes(32)
	fmt.Println(hex.EncodeToString(sender))

	receiver, _ := sink.NextBytes(32)
	fmt.Println(hex.EncodeToString(receiver))

	lengthNextParam, _ := sink.NextVarUint()
	fmt.Println(lengthNextParam)

	tokenID, _ := sink.NextBytes(lengthNextParam)
	fmt.Println(string(tokenID))

	lengthNextParam, _ = sink.NextVarUint()
	value, _ := sink.NextBytes(lengthNextParam)
	fmt.Println(big.NewInt(0).SetBytes(value).String())
}
