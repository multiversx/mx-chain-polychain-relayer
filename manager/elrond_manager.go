package manager

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

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
		wallet, err = polySdk.OpenWallet(cfg.PolyConfig.WalletFile)
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
			for em.currentHeight < latestBlockNonce {
				em.handleNewBlock(em.currentHeight + 1)
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

	ok = em.fetchLockDepositEvents(hyperblock)
	if !ok {
		log.Errorf("handleNewBlock - fetchLockDepositEvents on height :%d failed", blockHeight)
	}

	return true
}

func (em *ElrondManager) handlerNewBlockHeader(blockHeight uint64) (*data.Hyperblock, bool) {
	hyperblock, err := em.elrondClient.GetHyperblockByNonce(blockHeight)
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", blockHeight)
		return nil, false
	}

	decodedBlockHash, err := hex.DecodeString(hyperblock.Hash)
	if err != nil {
		log.Errorf("handleBlockHeader - cannot decode header hash: %s", err)
		return nil, false
	}

	hyberblockRaw, err := json.Marshal(hyperblock)
	if err != nil {
		log.Errorf("handleBlockHeader - cannot marshal header: %s", err)
		return nil, false
	}

	raw, _ := em.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(em.config.ElrondConfig.SideChainId)...), autils.GetUint64Bytes(blockHeight)...))
	if len(raw) == 0 || !bytes.Equal(raw, decodedBlockHash) {
		em.header4sync = append(em.header4sync, hyberblockRaw)
	}

	return hyperblock, true
}

func (em *ElrondManager) fetchLockDepositEvents(hyperblock *data.Hyperblock) bool {
	if len(hyperblock.Transactions) == 0 {
		log.Infof("MonitorChain elrond - no transaction in block %d\n", hyperblock.Nonce)
		return true
	}

	for _, tx := range hyperblock.Transactions {
		if tx.Receiver != em.config.ElrondConfig.CrossChainManagerContract {
			continue
		}

		if !strings.HasPrefix(string(tx.Data), "createCrossChainTx") {
			continue
		}

		crossChainTransfer, err := em.txProcessor.computeCrossChainTransfer(hyperblock.Nonce, tx)
		if err != nil {
			log.Errorf("Monitor chain fetchLockDepositEvents - cannot get cross chain transfer error: %s", err)
		}

		log.Infof("Monitor chain fetchLockDepositEvents parsed cross tx is: %+v\n", crossChainTransfer)

		sink := common.NewZeroCopySink(nil)
		crossChainTransfer.Serialization(sink)
		err = em.db.PutRetry(sink.Bytes())
		if err != nil {
			log.Errorf("Monitor chain fetchLockDepositEvents - em.db.PutRetry error: %s", err)
		}
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
