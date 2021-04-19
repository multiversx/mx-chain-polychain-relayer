package manager

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/ElrondNetwork/elrond-go/data/transaction"
	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	dataProxy "github.com/ElrondNetwork/elrond-proxy-go/data"
	"github.com/ElrondNetwork/elrond-sdk/erdgo"
	"github.com/ElrondNetwork/elrond-sdk/erdgo/blockchain"
	"github.com/ElrondNetwork/elrond-sdk/erdgo/data"
	"github.com/ontio/ontology-crypto/signature"
	common2 "github.com/polynetwork/poly/common"
	polytypes "github.com/polynetwork/poly/core/types"
	common3 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

type ElrondSender struct {
	proxyURL                       string
	privateKey                     []byte
	blockHeaderSyncContractAddress string
	crossChainManagementAddress    string
	address                        string
	client                         *tools.ElrondClient
}

func NewElrondSender(privKey []byte, cfg *config.ElrondConfig) (*ElrondSender, error) {
	elrondSender := &ElrondSender{
		privateKey:                     privKey,
		proxyURL:                       cfg.RestURL,
		blockHeaderSyncContractAddress: cfg.BlockHeaderSyncContract,
		crossChainManagementAddress:    cfg.CrossChainManagerContract,
	}

	account, err := elrondSender.getAccount()
	if err != nil {
		return nil, err
	}

	elrondSender.address = account.Address

	return elrondSender, nil
}

func (es *ElrondSender) CommitDepositEventsWithHeader(
	header *polytypes.Header,
	param *common3.ToMerkleValue,
	headerProof string,
	anchorHeader *polytypes.Header,
	polyTxHash string,
	rawAuditPath []byte,
) bool {
	var (
		sigs       []byte
		headerData []byte
	)
	if anchorHeader != nil && headerProof != "" {
		for _, sig := range anchorHeader.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	} else {
		for _, sig := range header.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	}

	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])

	res, err := es.checkIfFromChainTxExist(fromTx[:])
	if err != nil {
		log.Errorf("ElrondSender checkIfFromChainTxExist - failed to check transaction err: %v", err)
	}

	if res {
		log.Debugf("ElrondSender - already relayed to elrond: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
		return true
	}

	err = es.verifyHeader(header)
	if err != nil {
		log.Errorf("ElrondSender verifyHeader - failed to verify header err: %v", err)
	}

	_ = headerData

	// TODO continue implementation
	return true
}

func (es *ElrondSender) checkIfFromChainTxExist(txHash []byte) (bool, error) {
	vmRequest := &dataProxy.VmValueRequest{
		Address:    es.crossChainManagementAddress,
		FuncName:   "currentHeight",
		CallerAddr: "",
		CallValue:  "",
		Args:       []string{hex.EncodeToString(txHash)},
	}

	res, err := es.client.ExecuteQuery(vmRequest)
	if err != nil {
		return false, err
	}

	// TODO check response "exists" is not ok
	if bytes.Equal(res.Data.ReturnData[0], []byte("exists")) {
		return true, nil
	}

	return false, nil
}

func (es *ElrondSender) CommitHeader(header *polytypes.Header) error {
	return nil
}

func (es *ElrondSender) verifyHeader(header *polytypes.Header) error {
	sink := common2.NewZeroCopySink(nil)
	_ = header.Serialization(sink)

	ep := blockchain.NewElrondProxy(es.proxyURL)
	networkConfig, err := ep.GetNetworkConfig()
	if err != nil {
		return err
	}

	dataField := []byte("verifyHeader@" + hex.EncodeToString(sink.Bytes()))

	account, err := es.getAccount()
	if err != nil {
		return err
	}

	tx := &data.Transaction{
		Nonce:    account.Nonce,
		Value:    "0",
		RcvAddr:  es.blockHeaderSyncContractAddress,
		SndAddr:  account.Address,
		GasPrice: networkConfig.MinGasPrice,
		// TODO calculate gas
		GasLimit: networkConfig.MinGasLimit,
		Data:     dataField,
		ChainID:  networkConfig.ChainID,
		Version:  networkConfig.MinTransactionVersion,
	}

	err = erdgo.SignTransaction(tx, es.privateKey)
	if err != nil {
		return err
	}

	txHash, err := ep.SendTransaction(tx)
	if err != nil {
		return err
	}

	isSuccess := es.waitTransactionToBeExecuted(txHash)
	if !isSuccess {
		// TODO what we should do if transaction is failed or invalid
		return errors.New("transaction is not ok")
	}

	log.Infof("successful verify poly header to elrond: (header_hash: %s, height: %d))",
		txHash, header.Height)

	return nil
}

func (es *ElrondSender) GetBalance() (*big.Int, error) {
	account, err := es.getAccount()
	if err != nil {
		return nil, err
	}

	balanceBig, _ := big.NewInt(0).SetString(account.Balance, 10)
	return balanceBig, nil
}

func (es *ElrondSender) GetAddress() string {
	return es.address
}

func (es *ElrondSender) getAccount() (*data.Account, error) {
	ep := blockchain.NewElrondProxy(es.proxyURL)
	addressString, err := erdgo.GetAddressFromPrivateKey(es.privateKey)
	if err != nil {
		return nil, err
	}

	address, err := data.NewAddressFromBech32String(addressString)
	if err != nil {
		return nil, err
	}

	return ep.GetAccount(address)
}

func (es *ElrondSender) waitTransactionToBeExecuted(txHash string) bool {
	// TODO treat case when something went wrong with the transaction
	ep := blockchain.NewElrondProxy(es.proxyURL)
	for {
		time.Sleep(2 * time.Second)
		status, err := ep.GetTransactionStatus(txHash)
		if err != nil {
			continue
		}

		switch status {
		case transaction.TxStatusPending.String():
			continue
		case transaction.TxStatusSuccess.String():
			return true
		case transaction.TxStatusInvalid.String(), transaction.TxStatusFail.String():
			return false
		}
	}
}
