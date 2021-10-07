package tools

import (
	"bytes"
	"crypto/sha256"
	"github.com/polynetwork/poly/common"
)

func HashLeaf(leaf []byte) [32]byte {
	return sha256.Sum256(append([]byte{0x0}, leaf...))
}

func HashChildren(leftLeaf, rightLeaf []byte) [32]byte {
	leftLeaf = append([]byte{0x01}, leftLeaf...)
	return sha256.Sum256(append(leftLeaf, rightLeaf...))
}

func MerkleProve(auditPath, root []byte) []byte {
	path := common.NewZeroCopySource(auditPath)

	value, eof := path.NextVarBytes()
	hash := HashLeaf(value)
	if eof {
		return nil
	}
	size := path.Len() / 33

	for i := uint64(0); i < size; i++ {
		pos, _ := path.NextByte()
		nodeHash, _ := path.NextHash()
		if pos == 0x00 {
			hash = HashChildren(nodeHash[:], hash[:])
		} else if pos == 0x01 {
			hash = HashChildren(hash[:], nodeHash[:])
		} else {
			return nil
		}

	}
	if bytes.Equal(hash[:], root) {
		return value
	}
	return nil
}
