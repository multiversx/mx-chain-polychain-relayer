package manager

import (
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestElrondManager_getRawHyperblock(t *testing.T) {
	em := ElrondManager{
		elrondClient: tools.NewElrondClient("https://devnet-gateway.elrond.com"),
	}
	hyperblock, rawHyperblock, decodedBlockHash, err := em.getRawHyperblock(1612912)

	assert.NotNil(t, hyperblock)
	assert.NotNil(t, rawHyperblock)
	assert.NotNil(t, decodedBlockHash)
	assert.Nil(t, err)
}
