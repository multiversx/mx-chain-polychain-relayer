package manager

import (
	"fmt"

	"github.com/polynetwork/poly/common"
)

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (ct *CrossTransfer) Serialization(sink *common.ZeroCopySink) {
	sink.WriteString(ct.txIndex)
	sink.WriteVarBytes(ct.txId)
	sink.WriteVarBytes(ct.value)
	sink.WriteUint32(ct.toChain)
	sink.WriteUint64(ct.height)
}

func (ct *CrossTransfer) Deserialization(source *common.ZeroCopySource) error {
	txIndex, eof := source.NextString()
	if eof {
		return fmt.Errorf("waiting deserialize txIndex error")
	}
	txId, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("waiting deserialize txId error")
	}
	value, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("waiting deserialize value error")
	}
	toChain, eof := source.NextUint32()
	if eof {
		return fmt.Errorf("waiting deserialize toChain error")
	}
	height, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("waiting deserialize height error")
	}
	ct.txIndex = txIndex
	ct.txId = txId
	ct.value = value
	ct.toChain = toChain
	ct.height = height

	return nil
}
