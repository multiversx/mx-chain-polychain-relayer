package manager

import (
	"encoding/hex"
	"encoding/json"
	"github.com/ElrondNetwork/elrond-go-core/data/transaction"
	"github.com/ElrondNetwork/elrond-go-crypto/signing"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/ed25519"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/ed25519/singlesig"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/interactors"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/blockchain"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/data"
	vm "github.com/ElrondNetwork/elrond-sdk-erdgo/data"
	polytypes "github.com/polynetwork/poly/core/types"
	common3 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

const (
	DefaultGasLimit = 60000000
	ChanLen         = 64
)

type ErdTxInfo struct {
	tx         *data.Transaction
	polyTxHash string
}

type ElrondSender struct {
	proxyURL                       string
	privateKey                     []byte
	blockHeaderSyncContractAddress string
	crossChainManagementAddress    string
	address                        string
	routineNum                     int64
	cmap                           map[string]chan *ErdTxInfo
	client                         *tools.ElrondClient
}

func NewElrondSender(privKey []byte, cfg *config.ServiceConfig) (*ElrondSender, error) {
	elrondSender := &ElrondSender{
		privateKey:                     privKey,
		proxyURL:                       cfg.ElrondConfig.RestURL,
		blockHeaderSyncContractAddress: cfg.ElrondConfig.BlockHeaderSyncContract,
		crossChainManagementAddress:    cfg.ElrondConfig.CrossChainManagerContract,
		client:                         tools.NewElrondClient(cfg.ElrondConfig.RestURL),
		routineNum:                     cfg.RoutineNum,
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
		sigs []byte
	)
	if anchorHeader != nil && headerProof != "" {
		sigs = es.convertSignatures(anchorHeader.SigData)
	} else {
		sigs = es.convertSignatures(header.SigData)
	}

	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])

	res, err := es.checkIfFromChainTxExist(param.FromChainID, fromTx[:])
	if err != nil {
		log.Errorf("ElrondSender checkIfFromChainTxExist - failed to check transaction err: %v", err)
	}

	if res {
		log.Debugf("ElrondSender - already relayed to elrond: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
		return true
	}

	rawHeader := header.GetMessage()
	var rawAnchorHeader []byte
	if anchorHeader != nil {
		rawAnchorHeader = anchorHeader.GetMessage()
	}

	dataField := "verifyHeaderAndExecuteTx@" + hex.EncodeToString(rawAuditPath) + "@" + hex.EncodeToString(rawHeader) + "@" +
		headerProof + "@" + hex.EncodeToString(rawAnchorHeader) + "@" + hex.EncodeToString(sigs)

	tx, err := es.CreateTx([]byte(dataField), es.crossChainManagementAddress)
	if err != nil {
		return false
	}

	k := es.getRouter()
	c, ok := es.cmap[k]
	if !ok {
		c = make(chan *ErdTxInfo, ChanLen)
		es.cmap[k] = c
		go func() {
			for v := range c {
				if txHash, err := es.SendTx(v); err != nil {
					log.Errorf("failed to send tx to erd: error: %v, txHash: %s", err, txHash)
				}
			}
		}()
	}

	c <- &ErdTxInfo{
		tx:         tx,
		polyTxHash: polyTxHash,
	}

	return true
}

func (es *ElrondSender) GetCurrentEpochStartHeight(contractAddress string) (uint64, error) {

	vmRequest := &vm.VmValueRequest{
		Address:    contractAddress,
		FuncName:   "getCurrentEpochStartHeight",
		CallerAddr: "",
		CallValue:  "",
	}

	response, err := es.client.ExecuteQuery(vmRequest)
	if err != nil || response.Data.ReturnData == nil || len(response.Data.ReturnData[0]) == 0 {
		return 0, err
	}

	bigIntValue := big.NewInt(0).SetBytes(response.Data.ReturnData[0])
	startOfEpochHeight := bigIntValue.Uint64()

	return startOfEpochHeight, err
}

func (es *ElrondSender) checkIfFromChainTxExist(fromChainId uint64, txHash []byte) (bool, error) {

	vmRequest := &vm.VmValueRequest{
		Address:    es.crossChainManagementAddress,
		FuncName:   "txExists",
		CallerAddr: "",
		CallValue:  "",
		Args:       []string{hex.EncodeToString(txHash), hex.EncodeToString(tools.Uint64ToBytes(fromChainId))},
	}

	res, err := es.client.ExecuteQuery(vmRequest)
	if err != nil || res.Data.ReturnData == nil {
		return false, err
	}

	if len(res.Data.ReturnData[0]) > 0 && res.Data.ReturnData[0][0] == 1 {
		return true, nil
	}

	return false, nil
}

func (es *ElrondSender) CommitHeader(header *polytypes.Header, publicKeys []byte) error {
	var (
		sigs []byte
	)
	for _, sig := range header.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		newsig, _ := ConvertToErdCompatible(temp)
		sigs = append(sigs, newsig...)
	}

	rawHeader := header.GetMessage()

	dataField := "syncBlockHeader@" + hex.EncodeToString(rawHeader) + "@" +
		hex.EncodeToString(publicKeys) + "@" + hex.EncodeToString(sigs)

	tx, err := es.CreateTx([]byte(dataField), es.blockHeaderSyncContractAddress)
	if err != nil {
		return err
	}

	txHash, err := es.SendTx(&ErdTxInfo{tx: tx})
	if err != nil {
		log.Errorf("failed to relay poly header to erd: (header_hash: %s, height: %d, erd_txHash: %s, nonce: %d)",
			header.Hash(), header.Height, txHash, tx.Nonce)
		return err
	}
	log.Infof("successful send poly header to erd: (tx_hash: %s, height: %d))",
		txHash, header.Height)

	return nil
}

func (es *ElrondSender) CreateTx(dataValue []byte, rcvAddr string) (*data.Transaction, error) {
	account, err := es.getAccount()
	if err != nil {
		return nil, err
	}
	ep := blockchain.NewElrondProxy(es.proxyURL, nil)
	networkConfig, err := ep.GetNetworkConfig()
	if err != nil {
		return nil, err
	}

	tx := &data.Transaction{
		Nonce:    account.Nonce,
		Value:    "0",
		RcvAddr:  rcvAddr,
		SndAddr:  account.Address,
		GasPrice: networkConfig.MinGasPrice,
		GasLimit: DefaultGasLimit,
		Data:     dataValue,
		ChainID:  networkConfig.ChainID,
		Version:  networkConfig.MinTransactionVersion,
	}

	if err = es.SignTransaction(tx, es.privateKey); err != nil {
		return nil, err
	}

	gasLimit, err := ep.RequestTransactionCost(tx)
	if err != nil {
		tx.GasLimit = gasLimit.TxCost * 2
	}

	return tx, nil
}

func (es *ElrondSender) SendTx(txInfo *ErdTxInfo) (string, error) {
	ep := blockchain.NewElrondProxy(es.proxyURL, nil)

	txHash, err := ep.SendTransaction(txInfo.tx)
	if err != nil {
		return "", err
	}

	isSuccess := es.waitTransactionToBeExecuted(txHash)
	if isSuccess {
		log.Infof("successful to relay tx to erd: (erd_hash: %s, nonce: %d, poly_hash: %s, eth_explorer: %s)",
			txHash, txInfo.tx.Nonce, txInfo.polyTxHash)
	} else {
		log.Errorf("failed to relay tx to erd: (erd_hash: %s, nonce: %d poly_hash: %s, eth_explorer: %s)",
			txHash, txInfo.tx.Nonce, txInfo.polyTxHash)
	}

	return txHash, err
}

func (es *ElrondSender) getRouter() string {
	var router string

	for maxRetry := 10; maxRetry > 0; maxRetry-- {
		router = strconv.FormatInt(rand.Int63n(es.routineNum), 10)
		c, ok := es.cmap[router]
		if !ok {
			return router
		} else if len(c) < ChanLen {
			return router
		}
	}

	return strconv.FormatInt(rand.Int63n(es.routineNum), 10)
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
	ep := blockchain.NewElrondProxy(es.proxyURL, nil)
	wallet := interactors.NewWallet()
	addressString, err := wallet.GetAddressFromPrivateKey(es.privateKey)
	if err != nil {
		return nil, err
	}

	address, err := data.NewAddressFromBech32String(addressString.AddressAsBech32String())
	if err != nil {
		return nil, err
	}

	return ep.GetAccount(address)
}

func (es *ElrondSender) waitTransactionToBeExecuted(txHash string) bool {
	// TODO treat case when something went wrong with the

	maxRetry := 3

	ep := blockchain.NewElrondProxy(es.proxyURL, nil)
	for maxRetry > 0 {
		time.Sleep(2 * time.Second)
		status, err := ep.GetTransactionStatus(txHash)
		if err != nil && maxRetry > 0 {
			maxRetry--
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
	return false
}

func (es *ElrondSender) GetBookkeepers() []byte {
	ep := blockchain.NewElrondProxy(es.proxyURL, nil)

	request := &data.VmValueRequest{Address: es.blockHeaderSyncContractAddress,
		FuncName:   "getConsensusPeers",
		CallerAddr: es.GetAddress(),
		CallValue:  "0",
	}

	response, err := ep.ExecuteVMQuery(request)

	if err == nil && response.Data.ReturnData != nil && len(response.Data.ReturnData[0]) > 0 {
		return response.Data.ReturnData[0]
	}

	return nil
}

// SignTransaction signs a transaction with the provided private key
func (es *ElrondSender) SignTransaction(tx *data.Transaction, privateKey []byte) error {
	tx.Signature = ""
	txSingleSigner := &singlesig.Ed25519Signer{}
	suite := ed25519.NewEd25519()
	keyGen := signing.NewKeyGenerator(suite)
	txSignPrivKey, err := keyGen.PrivateKeyFromByteArray(privateKey)
	if err != nil {
		return err
	}
	bytes, err := json.Marshal(&tx)
	if err != nil {
		return err
	}
	signature, err := txSingleSigner.Sign(txSignPrivKey, bytes)
	if err != nil {
		return err
	}
	tx.Signature = hex.EncodeToString(signature)

	return nil
}

func (es *ElrondSender) convertSignatures(rawSigs [][]byte) []byte {
	var sigs []byte
	for _, sig := range rawSigs {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		newSig, _ := ConvertToErdCompatible(temp)
		sigs = append(sigs, newSig...)
	}
	return sigs
}
