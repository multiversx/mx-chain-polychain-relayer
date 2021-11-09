package manager

import (
	"encoding/hex"
	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strconv"
	"testing"
)

func TestIsEpoch(t *testing.T) {
	manager := &PolyManager{}

	header := GetMockHeader(120000)
	response, publickeys, err := manager.IsNewEpoch(header, GetMockRawBookkeepers)

	assert.True(t, response)
	assert.NotEmpty(t, publickeys)
	assert.Nil(t, err)

	header = GetMockHeader(120001)
	response, publickeys, err = manager.IsNewEpoch(header, GetMockRawBookkeepers)

	assert.False(t, response)
	assert.Nil(t, publickeys)
	assert.Nil(t, err)
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

func TestPolyManager_filterEvents(t *testing.T) {
	servConfig := config.NewServiceConfig("./testing/tconfig.json")
	manager := &PolyManager{}
	manager.cfg = servConfig

	manager.filterEvents(nil)
}

func TestPolyManager_verifySigs(t *testing.T) {
	manager := &PolyManager{}
	header := GetMockHeader(60001)

	result := manager.verifySigs(header)
	assert.True(t, result)

	manager.pks = GetMockRawBookkeepers()
	result = manager.verifySigs(header)
	assert.True(t, result)

	manager.pks = GetMockRawBookkeepers()[:57]
	result = manager.verifySigs(header)
	assert.False(t, result)
}

func TestPolyManager_verifyHeader(t *testing.T) {
	manager := PolyManager{}
	header := GetMockHeader(60001)
	anchor := GetMockHeader(120000)
	auditPath := GetMockProof()

	err := manager.verifyHeader(header, anchor, hex.EncodeToString(auditPath), false)
	assert.Nil(t, err)

	manager.pks = GetMockRawBookkeepers()
	header = GetMockHeader(60000)
	err = manager.verifyHeader(header, anchor, hex.EncodeToString(auditPath), true)
	assert.Nil(t, err)
}

func GetMockHeader(height int) *types.Header {
	rawHeader, err := ioutil.ReadFile("./testing/header" + strconv.Itoa(height))
	if err != nil {
		return nil
	}

	sink := common.NewZeroCopySource(rawHeader)
	header := types.Header{}
	err = header.Deserialization(sink)
	if err != nil {
		return nil
	}

	return &header
}

func GetMockRawBookkeepers() []byte {
	rawBookkeepers, err := ioutil.ReadFile("./testing/bookkeepers6000")
	if err != nil {
		return nil
	}

	return rawBookkeepers
}

func GetMockProof() []byte {
	rawProof, err := ioutil.ReadFile("./testing/proof_header60001_anchor_120000")
	if err != nil {
		return nil
	}

	return rawProof
}
