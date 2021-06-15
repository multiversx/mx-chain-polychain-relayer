package manager

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ElrondNetwork/elrond-go/hashing/keccak"
	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/db"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/ElrondNetwork/elrond-proxy-go/data"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	scom "github.com/polynetwork/poly/native/service/header_sync/common"
	autils "github.com/polynetwork/poly/native/service/utils"
)

type ElrondManager struct {
	config        *config.ServiceConfig
	elrondClient  *tools.ElrondClient
	currentHeight uint64
	height        uint64
	forceHeight   uint64
	polySdk       *sdk.PolySdk
	polySigner    *sdk.Account
	exitChan      chan int
	header4sync   [][]byte
	crosstx4sync  []*CrossTransfer
	db            *db.BoltDB
	txProcessor   *transactionProc
	lh            uint64
}

func NewElrondSyncManager(
	cfg *config.ServiceConfig,
	polySdk *sdk.PolySdk,
	elrondClient *tools.ElrondClient,
	boltDB *db.BoltDB,
) (*ElrondManager, error) {
	var wallet *sdk.Wallet
	var err error
	if !common.FileExisted(cfg.PolyConfig.WalletFile) {
		wallet, err = polySdk.CreateWallet(cfg.PolyConfig.WalletFile)
		if err != nil {
			return nil, err
		}
	} else {
		wallet, err = polySdk.OpenWallet(cfg.PolyConfig.WalletFile)
		if err != nil {
			log.Errorf("NewElrondSyncManager - wallet open error: %s", err.Error())
			return nil, err
		}
	}
	signer, err := wallet.GetDefaultAccount([]byte(cfg.PolyConfig.WalletPwd))
	if err != nil || signer == nil {
		signer, err = wallet.NewDefaultSettingAccount([]byte(cfg.PolyConfig.WalletPwd))
		if err != nil {
			log.Errorf("NewElrondSyncManager - wallet password error")
			return nil, err
		}

		err = wallet.Save()
		if err != nil {
			return nil, err
		}
	}

	log.Infof("NewElrondSyncManager - poly address: %s", signer.Address.ToBase58())

	txProc, err := NewTransactionsProcessor(cfg.ElrondConfig.CrossChainManagerContract, elrondClient)
	if err != nil {
		return nil, err
	}

	latestBlockNonce, _ := elrondClient.GetLatestHyperblockNonce()

	elrondSyncManager := &ElrondManager{
		config:       cfg,
		forceHeight:  cfg.ElrondConfig.ElrondForceHeight,
		polySdk:      polySdk,
		polySigner:   signer,
		exitChan:     make(chan int),
		db:           boltDB,
		elrondClient: elrondClient,
		txProcessor:  txProc,
		lh:           latestBlockNonce,
	}

	err = elrondSyncManager.init()
	if err != nil {
		return nil, err
	}

	return elrondSyncManager, nil
}

func (this *ElrondManager) MonitorChain() {
	fetchBlockTicker := time.NewTicker(time.Second * time.Duration(this.config.ElrondConfig.ElrondBlockMonitorIntervalInSeconds))
	var (
		blockHandleResult bool
		err               error
	)

	for {
		select {
		case <-fetchBlockTicker.C:
			latestBlockNonce, errGetNonce := this.elrondClient.GetLatestHyperblockNonce()
			if errGetNonce != nil {
				log.Infof("MonitorChain elrond - cannot get node height, err: %s", err)
				continue
			}

			if this.currentHeight >= latestBlockNonce {
				log.Infof("MonitorChain elrond - current height is not changed, skip")
				continue
			}

			blockHandleResult = true
			for this.currentHeight < latestBlockNonce {
				blockHandleResult = this.handleNewBlock(this.currentHeight + 1)
				if blockHandleResult == false {
					break
				}
				this.currentHeight++

				if len(this.header4sync) > this.config.ElrondConfig.HyperblockPerBatch {
					log.Infof("MonitorChain elrond - commit header")
					if res := this.commitHeader(); res != 0 {
						blockHandleResult = false
						break
					}
				}
			}
			if blockHandleResult && len(this.header4sync) > 0 {
				this.commitHeader()
			}
		case <-this.exitChan:
			return
		}
	}
}

func (this *ElrondManager) handleNewBlock(blockHeight uint64) bool {
	hyperblock, ok := this.handlerNewBlockHeader(blockHeight)
	if !ok {
		log.Errorf("handleNewBlock - handleBlockHeader on height :%d failed", blockHeight)
		return false
	}

	ok = this.fetchLockDepositEvents(hyperblock)
	if !ok {
		log.Errorf("handleNewBlock - fetchLockDepositEvents on height :%d failed", blockHeight)
	}

	return true
}

func (this *ElrondManager) handlerNewBlockHeader(blockHeight uint64) (*data.Hyperblock, bool) {
	hyperblock, err := this.elrondClient.GetHyperblockByNonce(blockHeight)
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", blockHeight)
		return nil, false
	}

	decodedBlockHash, err := hex.DecodeString(hyperblock.Hash)
	if err != nil {
		log.Errorf("handleBlockHeader - cannot decode header hash: %s", err)
		return nil, false
	}

	//hyperblockWithoutTxs:= hyperblock
	//hyperblockWithoutTxs.Transactions = nil
	hyberblockRaw, err := json.Marshal(hyperblock)
	if err != nil {
		log.Errorf("handleBlockHeader - cannot marshal header: %s", err)
		return nil, false
	}

	fmt.Printf(hyperblock.Hash)
	fmt.Printf(string(hyberblockRaw[:]))

	raw, _ := this.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(this.config.ElrondConfig.SideChainId)...), autils.GetUint64Bytes(blockHeight)...))
	if len(raw) == 0 || !bytes.Equal(raw, decodedBlockHash) {
		this.header4sync = append(this.header4sync, hyberblockRaw)
	}

	return hyperblock, true
}

func (this *ElrondManager) fetchLockDepositEvents(hyperblock *data.Hyperblock) bool {
	if len(hyperblock.Transactions) == 0 {
		log.Infof("MonitorChain elrond - no transaction in block %d\n", hyperblock.Nonce)
		return true
	}

	for _, tx := range hyperblock.Transactions {
		if tx.Receiver != this.config.ElrondConfig.CrossChainManagerContract {
			continue
		}

		if !strings.Contains(string(tx.Data), "63726561746543726F7373436861696E5478") {
			continue
		}

		crossChainTransfer, err := this.txProcessor.computeCrossChainTransfer(hyperblock.Nonce, tx)
		if err != nil {
			log.Errorf("Monitor chain fetchLockDepositEvents - cannot get cross chain transfer error: %s", err)
		}

		log.Infof("Monitor chain fetchLockDepositEvents parsed cross tx is: %+v\n", crossChainTransfer)

		sink := common.NewZeroCopySink(nil)
		crossChainTransfer.Serialization(sink)
		err = this.db.PutRetry(sink.Bytes())
		if err != nil {
			log.Errorf("Monitor chain fetchLockDepositEvents - this.db.PutRetry error: %s", err)
		}
	}

	return true
}

func (this *ElrondManager) commitHeader() int {
	start := time.Now()
	tx, err := this.polySdk.Native.Hs.SyncBlockHeader(
		this.config.ElrondConfig.SideChainId,
		this.polySigner.Address,
		this.header4sync,
		this.polySigner,
	)
	if err != nil {
		errDesc := err.Error()
		if strings.Contains(errDesc, "get the parent block failed") || strings.Contains(errDesc, "missing required field") {
			log.Warnf("commitHeader - send transaction to poly chain err: %s", errDesc)
			this.rollBackToCommAncestor()
			return 0
		} else {
			log.Errorf("commitHeader - send transaction to poly chain err: %s", errDesc)
			return 1
		}
	}

	tick := time.NewTicker(100 * time.Millisecond)
	var h uint32
	for range tick.C {
		h, _ = this.polySdk.GetBlockHeightByTxHash(tx.ToHexString())
		curr, _ := this.polySdk.GetCurrentBlockHeight()
		log.Infof("MonitorChain GetBlockHeightByTxHash h:%d curr:%d waited:%v", h, curr, time.Now().Sub(start))
		if h > 0 && curr > h {
			break
		}
	}
	log.Infof("MonitorChain elrond - commitHeader - send transaction"+
		" %s to poly chain and confirmed on height %d, synced elrond height %d, elrond height %d, took %s, header count %d",
		tx.ToHexString(), h, this.currentHeight, this.height, time.Now().Sub(start).String(), len(this.header4sync))

	this.header4sync = make([][]byte, 0)

	return 0
}

func (em *ElrondManager) init() error {
	// get latest height
	latestHeight := em.findLatestHeight()
	if latestHeight == 0 {
		return errors.New("init - the genesis block has not synced")
	}

	if em.forceHeight > 0 && em.forceHeight < latestHeight {
		em.currentHeight = em.forceHeight
	} else {
		em.currentHeight = latestHeight
	}

	log.Infof("BSCManager init - start height: %d", em.currentHeight)

	return nil
}

func (em *ElrondManager) findLatestHeight() uint64 {
	// try to get key
	/*var sideChainIdBytes [8]byte
	binary.LittleEndian.PutUint64(sideChainIdBytes[:], em.config.ElrondConfig.SideChainId)
	contractAddress := autils.HeaderSyncContractAddress
	key := append([]byte(scom.CURRENT_HEADER_HEIGHT), sideChainIdBytes[:]...)
	// try to get storage
	result, err := em.polySdk.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		log.Infof("get latest tx block from poly failed,err: %s\n", err.Error())
		return 0
	}
	if result == nil || len(result) == 0 {
		return 0
	}

	return binary.LittleEndian.Uint64(result)*/

	em.lh ++
	return em.lh
}

func (em *ElrondManager) rollBackToCommAncestor() {
	for ; ; em.currentHeight-- {
		raw, err := em.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
			append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(em.config.ElrondConfig.SideChainId)...), autils.GetUint64Bytes(em.currentHeight)...))
		if len(raw) == 0 || err != nil {
			continue
		}

		hdr, err := em.elrondClient.GetHyperblockByNonce(em.currentHeight)
		if err != nil {
			log.Errorf("rollBackToCommAncestor - failed to get header by number, so we wait for one second to retry: %v", err)
			time.Sleep(time.Second)
			em.currentHeight++
		}

		decodedHeaderHash, _ := hex.DecodeString(hdr.Hash)
		if bytes.Equal(decodedHeaderHash, raw) {
			log.Infof("rollBackToCommAncestor - find the common ancestor: %s(number: %d)", hdr.Hash, em.currentHeight)
			break
		}
	}
	em.header4sync = make([][]byte, 0)
}

func (this *ElrondManager) commitProof(height uint32, proof []byte, value []byte, txhash []byte) (string, error) {
	log.Debugf("commit proof, height: %d, proof: %s, value: %s, txhash: %s", height, string(proof), hex.EncodeToString(value), hex.EncodeToString(txhash))
	var address, _ = hex.DecodeString(this.polySigner.Address.ToHexString())
	var hasher = keccak.Keccak{}
	tx, err := this.polySdk.Native.Ccm.ImportOuterTransfer(
		this.config.ElrondConfig.SideChainId,
		value,
		height,
		proof,
		address,
		[]byte{},
		this.polySigner)
	//TODO: delete mock value
	if err != nil {
		return "736f6d65206d6f636b", nil
	} else {
		log.Infof("commitProof - send transaction to poly chain: ( poly_txhash: %s, eth_txhash: %s, height: %d )",
			tx.ToHexString(), string(hasher.Compute(string(txhash))), height)
		return tx.ToHexString(), nil
	}
}

func (this *ElrondManager) CheckDeposit() {
	checkTicker := time.NewTicker(time.Duration(this.config.ElrondConfig.ElrondBlockMonitorIntervalInSeconds) * time.Second)
	for {
		select {
		case <-checkTicker.C:
			// try to check deposit
			this.checkLockDepositEvents()
		case <-this.exitChan:
			return
		}
	}
}
type SCEvent struct {
	TxHash string
	State  byte
}
func (this *ElrondManager) checkLockDepositEvents() error {
	checkMap, err := this.db.GetAllCheck()

	if err != nil {
		return fmt.Errorf("checkLockDepositEvents - this.db.GetAllCheck error: %s", err)
	}
	for k, v := range checkMap {
		log.Infof("check lock deposit events %s",k)
		//event, err := this.polySdk.GetSmartContractEvent(k)
		//TODO: delete this
		err = nil
		event := &SCEvent{TxHash: "MOCK TX HASH",State: 1}
		if err != nil {
			log.Errorf("checkLockDepositEvents - this.polySdk.GetSmartContractEvent error: %s", err)
			continue
		}
		if event == nil {
			continue
		}
		if event.State != 1 {
			log.Infof("checkLockDepositEvents - state of poly tx %s is not success", k)
			err := this.db.PutRetry(v)
			if err != nil {
				log.Errorf("checkLockDepositEvents - this.db.PutRetry error:%s", err)
			}
		}
		err = this.db.DeleteCheck(k)
		if err != nil {
			log.Errorf("checkLockDepositEvents - this.db.DeleteRetry error:%s", err)
		}
	}
	return nil
}

func (this *ElrondManager) MonitorDeposit() {
	monitorTicker := time.NewTicker(time.Duration(this.config.ElrondConfig.ElrondBlockMonitorIntervalInSeconds) * time.Second)
	for {
		select {
		case <-monitorTicker.C:
			height, err := this.elrondClient.GetLatestHyperblockNonce()
			if err != nil {
				log.Infof("MonitorDeposit - cannot get node height, err: %s", err)
				continue
			}
			snycheight := this.findLatestHeight()
			log.Log.Info("MonitorDeposit from erd - snyced height", snycheight, "height", height, "diff", int64(height-snycheight))
			this.handleLockDepositEvents(snycheight)
		case <-this.exitChan:
			return
		}
	}
}

func (this *ElrondManager) handleLockDepositEvents(refHeight uint64) error {
	retryList, err := this.db.GetAllRetry()
	if err != nil {
		return fmt.Errorf("handleLockDepositEvents - this.db.GetAllRetry error: %s", err)
	}

	for _, v := range retryList {
		time.Sleep(time.Second * 1)
		crosstx := new(CrossTransfer)
		err := crosstx.Deserialization(common.NewZeroCopySource(v))
		if err != nil {
			log.Errorf("handleLockDepositEvents - retry.Deserialization error: %s", err)
			continue
		}
		log.Infof(" handleLockDepositEvents : %s", crosstx)
		//TODO: decode events
		height := refHeight
		//TODO: get proof
		proof := getProof()
		//TODO: commit proof to poly
		txHash, err := this.commitProof(uint32(height), proof, crosstx.value, crosstx.txId)
		if err != nil {
			if strings.Contains(err.Error(), "chooseUtxos, current utxo is not enough") {
				log.Infof("handleLockDepositEvents - invokeNativeContract error: %s", err)
				continue
			} else {
				if err := this.db.DeleteRetry(v); err != nil {
					log.Errorf("handleLockDepositEvents - this.db.DeleteRetry error: %s", err)
				}
				if strings.Contains(err.Error(), "tx already done") {
					log.Debugf("handleLockDepositEvents - tx already on poly")
				}
				continue
			}
		}
		//put to check db for checking
		err = this.db.PutCheck(txHash, v)
		if err != nil {
			log.Errorf("handleLockDepositEvents - this.db.PutCheck error: %s", err)
		}
		err = this.db.DeleteRetry(v)
		if err != nil {
			log.Errorf("handleLockDepositEvents - delete retry error: %s", err)
		}
		//log.Infof("handleLockDepositEvents - syncProofToAlia txHash is %s", txHash)
	}

	return nil
}

func getProof() []byte {
	return []byte{1,2,3}
}
