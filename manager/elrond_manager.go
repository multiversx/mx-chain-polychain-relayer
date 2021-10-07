package manager

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/data"
	"github.com/ontio/ontology/smartcontract/service/native/cross_chain/cross_chain_manager"
	"strings"
	"time"

	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/db"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
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

	elrondSyncManager := &ElrondManager{
		config:       cfg,
		forceHeight:  cfg.ElrondConfig.ElrondForceHeight,
		polySdk:      polySdk,
		polySigner:   signer,
		exitChan:     make(chan int),
		db:           boltDB,
		elrondClient: elrondClient,
		txProcessor:  txProc,
	}

	err = elrondSyncManager.init()
	if err != nil {
		return nil, err
	}

	return elrondSyncManager, nil
}

func (em *ElrondManager) MonitorChain() {
	fetchBlockTicker := time.NewTicker(time.Second * time.Duration(em.config.ElrondConfig.ElrondBlockMonitorIntervalInSeconds))
	var (
		blockHandleResult bool
		err               error
	)

	for {
		select {
		case <-fetchBlockTicker.C:
			latestBlockNonce, errGetNonce := em.elrondClient.GetLatestHyperblockNonce()
			if errGetNonce != nil {
				log.Infof("MonitorChain elrond - cannot get node height, err: %s", err)
				continue
			}

			if em.currentHeight >= latestBlockNonce {
				log.Infof("MonitorChain elrond - current height is not changed, skip")
				continue
			}

			blockHandleResult = true
			for em.currentHeight < latestBlockNonce-config.ERD_USEFUL_BLOCK_NUM {
				blockHandleResult = em.handleNewBlock(em.currentHeight + 1)
				if blockHandleResult == false {
					break
				}
				em.currentHeight++

				if len(em.header4sync) > em.config.ElrondConfig.HyperblockPerBatch {
					log.Infof("MonitorChain elrond - commit header")
					if res := em.commitHeader(); res != 0 {
						blockHandleResult = false
						break
					}
				}
			}
			if blockHandleResult && len(em.header4sync) > 0 {
				em.commitHeader()
			}
		case <-em.exitChan:
			return
		}
	}
}

func (em *ElrondManager) handleNewBlock(blockHeight uint64) bool {
	hyperblock, ok := em.handlerNewBlockHeader(blockHeight)
	if !ok {
		log.Errorf("handleNewBlock - handleBlockHeader on height :%d failed", blockHeight)
		return false
	}

	ok = em.fetchLockDepositEvents(hyperblock.Nonce)
	if !ok {
		log.Errorf("handleNewBlock - fetchLockDepositEvents on height :%d failed", blockHeight)
	}

	return true
}

func (em *ElrondManager) handlerNewBlockHeader(blockHeight uint64) (*data.HyperBlock, bool) {
	hyperblock, rawHyperblock, decodedBlockHash, err := em.getRawHyperblock(blockHeight)
	if err != nil {
		log.Errorf(err.Error())
		return nil, false
	}

	raw, _ := em.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(em.config.ElrondConfig.SideChainId)...), autils.GetUint64Bytes(blockHeight)...))
	if len(raw) == 0 || !bytes.Equal(raw, decodedBlockHash) {
		em.header4sync = append(em.header4sync, rawHyperblock)
	}

	return hyperblock, true
}

func (em *ElrondManager) fetchLockDepositEvents(nonce uint64) bool {
	transactions := em.elrondClient.GetTransactionsForHyperblock(nonce)
	if len(transactions) == 0 {
		log.Infof("MonitorChain elrond - no transaction in block %d\n", nonce)
		return true
	}

	for _, tx := range transactions {
		if tx.Receiver != em.config.ElrondConfig.CrossChainManagerContract {
			continue
		}

		if !strings.Contains(string(tx.Data), "createCrossChainTx") {
			continue
		}

		crossChainTransfer, crossChainTxId, assetHash, toChainId, err := em.txProcessor.computeCrossChainTransfer(tx.Hash, nonce)
		if err != nil {
			log.Errorf("Monitor chain fetchLockDepositEvents - cannot get cross chain transfer error: %s", err)
		}

		log.Infof("Monitor chain fetchLockDepositEvents parsed cross tx is: %+v\n", crossChainTransfer)

		var isTarget bool
		if len(em.config.TargetContracts) > 0 {
			toContractStr := string(assetHash)
			for _, v := range em.config.TargetContracts {
				toChainIdArr, ok := v[toContractStr]
				if ok {
					if len(toChainIdArr["outbound"]) == 0 {
						isTarget = true
						break
					}
					for _, id := range toChainIdArr["outbound"] {
						if id == toChainId {
							isTarget = true
							break
						}
					}
					if isTarget {
						break
					}
				}
			}
			if !isTarget {
				continue
			}
		}

		raw, _ := em.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(cross_chain_manager.DONE_TX), autils.GetUint64Bytes(em.config.ElrondConfig.SideChainId)...), crossChainTxId...))
		if len(raw) != 0 {
			log.Debugf("fetchLockDepositEvents - ccid %s  already on poly",
				hex.EncodeToString(crossChainTxId))
			continue
		}

		sink := common.NewZeroCopySink(nil)
		crossChainTransfer.Serialization(sink)
		err = em.db.PutRetry(sink.Bytes())
		if err != nil {
			log.Errorf("Monitor chain fetchLockDepositEvents - this.db.PutRetry error: %s", err)
		}
		log.Infof("fetchLockDepositEvent -  height: %d", nonce)
	}

	return true
}

func (em *ElrondManager) commitHeader() int {
	start := time.Now()
	tx, err := em.polySdk.Native.Hs.SyncBlockHeader(
		em.config.ElrondConfig.SideChainId,
		em.polySigner.Address,
		em.header4sync,
		em.polySigner,
	)
	if err != nil {
		errDesc := err.Error()
		if strings.Contains(errDesc, "get the parent block failed") || strings.Contains(errDesc, "missing required field") {
			log.Warnf("commitHeader - send transaction to poly chain err: %s", errDesc)
			em.rollBackToCommAncestor()
			return 0
		} else {
			log.Errorf("commitHeader - send transaction to poly chain err: %s", errDesc)
			return 1
		}
	}

	tick := time.NewTicker(100 * time.Millisecond)
	var h uint32
	for range tick.C {
		h, _ = em.polySdk.GetBlockHeightByTxHash(tx.ToHexString())
		curr, _ := em.polySdk.GetCurrentBlockHeight()
		log.Infof("MonitorChain GetBlockHeightByTxHash h:%d curr:%d waited:%v", h, curr, time.Now().Sub(start))
		if h > 0 && curr > h {
			break
		}
	}
	log.Infof("MonitorChain elrond - commitHeader - send transaction"+
		" %s to poly chain and confirmed on height %d, synced elrond height %d, elrond height %d, took %s, header count %d",
		tx.ToHexString(), h, em.currentHeight, em.height, time.Now().Sub(start).String(), len(em.header4sync))

	em.header4sync = make([][]byte, 0)

	return 0
}

func (em *ElrondManager) init() error {
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
	var sideChainIdBytes [8]byte
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

	return binary.LittleEndian.Uint64(result)
}

func (em *ElrondManager) rollBackToCommAncestor() {
	for ; ; em.currentHeight-- {
		raw, err := em.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
			append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(em.config.ElrondConfig.SideChainId)...), autils.GetUint64Bytes(em.currentHeight)...))
		if len(raw) == 0 || err != nil {
			continue
		}

		hdr, err := em.elrondClient.GetHyperblockByNonce(em.currentHeight)
		if err != nil || hdr == nil {
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
	tx, err := this.polySdk.Native.Ccm.ImportOuterTransfer(
		this.config.ElrondConfig.SideChainId,
		value,
		height,
		proof,
		address,
		[]byte{},
		this.polySigner)
	if err != nil {
		return "", nil
	} else {
		log.Infof("commitProof - send transaction to poly chain: ( poly_txhash: %s, height: %d )",
			tx.ToHexString(), height)
		return tx.ToHexString(), nil
	}
}

func (em *ElrondManager) CheckDeposit() {
	checkTicker := time.NewTicker(time.Duration(em.config.ElrondConfig.ElrondBlockMonitorIntervalInSeconds) * time.Second)
	for {
		select {
		case <-checkTicker.C:
			em.checkLockDepositEvents()
		case <-em.exitChan:
			return
		}
	}
}

func (em *ElrondManager) checkLockDepositEvents() error {
	checkMap, err := em.db.GetAllCheck()

	if err != nil {
		return fmt.Errorf("checkLockDepositEvents - this.db.GetAllCheck error: %s", err)
	}
	for k, v := range checkMap {
		log.Infof("check lock deposit events %s", k)
		event, err := em.polySdk.GetSmartContractEvent(k)
		if err != nil {
			log.Errorf("checkLockDepositEvents - this.polySdk.GetSmartContractEvent error: %s", err)
			continue
		}
		if event == nil {
			continue
		}
		if event.State != 1 {
			log.Infof("checkLockDepositEvents - state of poly tx %s is not success", k)
			err := em.db.PutRetry(v)
			if err != nil {
				log.Errorf("checkLockDepositEvents - this.db.PutRetry error:%s", err)
			}
		}
		err = em.db.DeleteCheck(k)
		if err != nil {
			log.Errorf("checkLockDepositEvents - this.db.DeleteRetry error:%s", err)
		}
	}
	return nil
}

func (em *ElrondManager) MonitorDeposit() {
	monitorTicker := time.NewTicker(time.Duration(em.config.ElrondConfig.ElrondBlockMonitorIntervalInSeconds) * time.Second)
	for {
		select {
		case <-monitorTicker.C:
			height, err := em.elrondClient.GetLatestHyperblockNonce()
			if err != nil {
				log.Infof("MonitorDeposit - cannot get node height, err: %s", err)
				continue
			}
			snycheight := em.findLatestHeight()
			log.Log.Info("MonitorDeposit from erd - snyced height", snycheight, "height", height, "diff", int64(height-snycheight))
			em.handleLockDepositEvents(snycheight)
		case <-em.exitChan:
			return
		}
	}
}

func (em *ElrondManager) handleLockDepositEvents(refHeight uint64) error {
	retryList, err := em.db.GetAllRetry()
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
		// decode events
		key := crosstx.txIndex
		proofKey := hex.EncodeToString([]byte(key))
		hyperblock, _ := em.elrondClient.GetHyperblockByNonce(refHeight)
		dataTrieProof, dataTrieRootHash, mainTrieProof, err := em.elrondClient.GetProof("nodeUrl", hyperblock.Hash, em.config.ElrondConfig.CrossChainManagerContract, proofKey)
		if err != nil {
			log.Errorf("handleLockDepositEvents - error :%s\n", err.Error())
			continue
		}
		proof := common.NewZeroCopySink(nil)
		proof.WriteVarBytes([]byte(dataTrieProof))
		proof.WriteVarBytes([]byte(dataTrieRootHash))
		mainTrieProofSink := common.NewZeroCopySink(nil)
		for _, value := range mainTrieProof {
			mainTrieProofSink.WriteVarBytes([]byte(value))
		}
		proof.WriteVarBytes(mainTrieProofSink.Bytes())

		// commit proof to poly
		txHash, err := em.commitProof(uint32(refHeight), proof.Bytes(), crosstx.value, crosstx.txId)
		if err != nil {
			if strings.Contains(err.Error(), "chooseUtxos, current utxo is not enough") {
				log.Infof("handleLockDepositEvents - invokeNativeContract error: %s", err)
				continue
			} else {
				if err := em.db.DeleteRetry(v); err != nil {
					log.Errorf("handleLockDepositEvents - this.db.DeleteRetry error: %s", err)
				}
				if strings.Contains(err.Error(), "tx already done") {
					log.Debugf("handleLockDepositEvents - tx already on poly")
				}
				continue
			}
		}
		//put to check db for checking
		err = em.db.PutCheck(txHash, v)
		if err != nil {
			log.Errorf("handleLockDepositEvents - this.db.PutCheck error: %s", err)
		}
		err = em.db.DeleteRetry(v)
		if err != nil {
			log.Errorf("handleLockDepositEvents - delete retry error: %s", err)
		}
		log.Infof("handleLockDepositEvents - syncProofToAlia txHash is %s", txHash)
	}

	return nil
}

func (em *ElrondManager) getRawHyperblock(height uint64) (*data.HyperBlock, []byte, []byte, error) {
	hyperblock, err := em.elrondClient.GetHyperblockByNonce(height)
	if err != nil {
		return nil, nil, nil, errors.New(fmt.Sprintf("handleBlockHeader - GetNodeHeader on height :%d failed", height))
	}

	decodedBlockHash, err := hex.DecodeString(hyperblock.Hash)
	if err != nil {
		return nil, nil, nil, errors.New(fmt.Sprintf("handleBlockHeader - cannot decode header hash: %s", err))
	}

	hyberBlockRaw, err := json.Marshal(hyperblock)
	if err != nil {
		return nil, nil, nil, errors.New(fmt.Sprintf("handleBlockHeader - cannot marshal header: %s", err))
	}

	return hyperblock, hyberBlockRaw, decodedBlockHash, nil
}
