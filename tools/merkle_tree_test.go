package tools

import (
	"encoding/hex"
	"fmt"
	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMerkleProveHeader(t *testing.T) {

	polySdk := sdk.NewPolySdk()
	servConfig := config.NewServiceConfig("../config.json")
	if servConfig == nil {
		return
	}

	_ = SetUpPoly(polySdk, servConfig.PolyConfig.RestURL)
	height := uint32(59999)

	header, _ := polySdk.GetHeaderByHeight(height + 1)

	anchor, _ := polySdk.GetHeaderByHeight(height + 2)
	proof, _ := polySdk.GetMerkleProof(height+1, height+2)
	hp := proof.AuditPath

	fmt.Println("header proof: " + hp)
	fmt.Println("Block Root: " + hex.EncodeToString(anchor.BlockRoot.ToArray()))

	rawProof, _ := hex.DecodeString(hp)

	rawHeaderHash := MerkleProve(rawProof, anchor.BlockRoot[:])

	fmt.Println("rawHeaderHash " + hex.EncodeToString(rawHeaderHash))

	assert.NotNil(t, rawHeaderHash)
	hash := header.Hash()
	assert.Equal(t, hash.ToArray(), rawHeaderHash)

}

func SetUpPoly(poly *sdk.PolySdk, rpcAddr string) error {
	poly.NewRpcClient().SetAddress(rpcAddr)

	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}

	poly.SetChainId(hdr.ChainID)

	return nil
}
