package manager

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/db"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/ElrondNetwork/elrond-sdk/erdgo"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	polytypes "github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

type PolyManager struct {
	syncedHeight uint32
	polySdk      *poly_go_sdk.PolySdk
	exitChan     chan int
	db           *db.BoltDB
	cfg          *config.ServiceConfig

	elrondClient           *tools.ElrondClient
	crossChainManager      string
	crossChainManagerProxy string
	senders                []*ElrondSender
}

func (pm *PolyManager) init() bool {
	if pm.syncedHeight > 0 {
		log.Infof("PolyManager init - start height from flag: %d", pm.syncedHeight)
		return true
	}

	pm.syncedHeight = pm.db.GetPolyHeight()
	latestHeight := pm.findLatestHeight()
	if latestHeight > pm.syncedHeight {
		pm.syncedHeight = latestHeight
		log.Infof("PolyManager init - synced height from ECCM: %d", pm.syncedHeight)
		return true
	}

	log.Infof("PolyManager init - synced height from DB: %d", pm.syncedHeight)

	return true
}

func (pm *PolyManager) findLatestHeight() uint32 {
	epochStartHeight, err := pm.elrondClient.GetCurrentEpochStartHeight(pm.cfg.ElrondConfig.BlockHeaderSyncContract, pm.cfg.PolyConfig.ChainID)
	if err != nil {
		log.Errorf("findLatestHeight - GetEpochStartHeight failed: %s", err.Error())
		return 0
	}

	return uint32(epochStartHeight)
}

func NewPolyManager(cfg *config.ServiceConfig, polySdk *poly_go_sdk.PolySdk, elrondClient *tools.ElrondClient, boltDB *db.BoltDB) (*PolyManager, error) {
	senders := make([]*ElrondSender, 0)

	keysStoreFiles, err := tools.GetAllKeyStoreFiles(cfg.ElrondConfig.KeyStorePath)
	if err != nil {
		return nil, fmt.Errorf("no keys store files provided")
	}

	keysStoreFilesPW := cfg.ElrondConfig.KeyStorePwdSet

	for _, keyStore := range keysStoreFiles {
		bech32Addr, errGetAddr := tools.GetBech32AddressFromKeystoreFile(keyStore)
		if errGetAddr != nil {
			return nil, errGetAddr
		}

		privKey, errLoad := erdgo.LoadPrivateKeyFromJsonFile(keyStore, keysStoreFilesPW[bech32Addr])
		if errLoad != nil {
			return nil, errLoad
		}

		sender, errSender := NewElrondSender(privKey, cfg.ElrondConfig)
		if errSender != nil {
			continue
		}

		senders = append(senders, sender)
	}

	polyManager := &PolyManager{
		syncedHeight:      cfg.PolyConfig.PolyStartHeight,
		polySdk:           polySdk,
		exitChan:          make(chan int),
		db:                boltDB,
		cfg:               cfg,
		elrondClient:      elrondClient,
		crossChainManager: cfg.ElrondConfig.CrossChainManagerContract,
		senders:           senders,
	}

	return polyManager, nil
}

func (pm *PolyManager) MonitorChain() {
	fetchBlockTicker := time.NewTicker(time.Second * time.Duration(pm.cfg.PolyConfig.PolyMonitorIntervalSeconds))
	var blockHandleResult bool

	for {
		select {
		case <-fetchBlockTicker.C:
			latestHeight, err := pm.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("PolyManager - cannot get node height, err: %s\n", err.Error())
				continue
			}

			latestHeight--
			if latestHeight-pm.syncedHeight < pm.cfg.PolyConfig.OntUsefulBlocksNum {
				log.Infof("PolyManager - poly chain skip current height: %d", latestHeight)
				continue
			}

			log.Infof("PolyManager - poly chain current height: %d", latestHeight)
			blockHandleResult = true
			for pm.syncedHeight <= latestHeight-pm.cfg.PolyConfig.OntUsefulBlocksNum {
				if pm.syncedHeight%10 == 0 {
					log.Infof("handle confirmed poly Block height: %d", pm.syncedHeight)
				}
				blockHandleResult = pm.handleDepositEvents(pm.syncedHeight, latestHeight)
				if blockHandleResult == false {
					break
				}
				pm.syncedHeight++
			}
			if err = pm.db.UpdatePolyHeight(pm.syncedHeight - 1); err != nil {
				log.Errorf("PolyManager - failed to save height of poly: %v", err)
			}
		case <-pm.exitChan:
			return

		}
	}
}

func (pm *PolyManager) handleDepositEvents(height, latest uint32) bool {
	log.Infof("PolyManager handleDepositEvents at height %d, latest height %d\n", height, latest)

	latestEpochStartHeight := pm.findLatestHeight()
	hdr, err := pm.polySdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("PolyManager handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}

	isCurr := latestEpochStartHeight <= height
	info := &vconfig.VbftBlockInfo{}

	err = json.Unmarshal(hdr.ConsensusPayload, info)
	if err != nil {
		log.Errorf("PolyManager failed to unmarshal ConsensusPayload for height %d: %v", height+1, err)
		return false
	}

	isEpoch := hdr.NextBookkeeper != common.ADDRESS_EMPTY && info.NewChainConfig != nil

	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = pm.polySdk.GetHeaderByHeight(latestEpochStartHeight + 1)
		proof, _ := pm.polySdk.GetMerkleProof(height+1, latestEpochStartHeight+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = pm.polySdk.GetHeaderByHeight(height + 2)
		proof, _ := pm.polySdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	cnt := 0
	events, err := pm.polySdk.GetSmartContractEventByBlock(height)
	if err != nil {
		log.Errorf("PolyManager handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
	}

	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress != pm.cfg.PolyConfig.EntranceContractAddress {
				continue
			}

			states := notify.States.([]interface{})
			method, _ := states[0].(string)
			if method != "makeProof" {
				continue
			}

			if uint64(states[2].(float64)) != pm.cfg.ElrondConfig.SideChainId {
				continue
			}

			proof, errGetProf := pm.polySdk.GetCrossStatesProof(hdr.Height-1, states[5].(string))
			if errGetProf != nil {
				log.Errorf("PolyManager handleDepositEvents - failed to get proof for key %s: %v", states[5].(string), err)
				continue
			}

			auditpath, _ := hex.DecodeString(proof.AuditPath)
			value, _, _, _ := tools.ParseAuditpath(auditpath)
			param := &common2.ToMerkleValue{}
			if errDes := param.Deserialization(common.NewZeroCopySource(value)); errDes != nil {
				log.Errorf("PolyManager handleDepositEvents - failed to deserialize MakeTxParam (value: %x, err: %v)", value, err)
				continue
			}

			var isTarget bool
			if len(pm.cfg.TargetContracts) > 0 {
				toContractStr := tools.ToElrondAddress(param.MakeTxParam.ToContractAddress)
				for _, v := range pm.cfg.TargetContracts {
					toChainIdArr, ok := v[toContractStr]
					if ok {
						if len(toChainIdArr["inbound"]) == 0 {
							isTarget = true
							break
						}
						for _, id := range toChainIdArr["inbound"] {
							if id == param.FromChainID {
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

				cnt++
				sender := pm.selectSender()
				sender.CommitDepositEventsWithHeader(hdr, param, hp, anchor, event.TxHash, auditpath)
			}
		}
	}

	if !(cnt == 0 && isEpoch && isCurr) {
		return true
	}

	sender := pm.selectSender()
	err = sender.CommitHeader(hdr)
	if err != nil {
		log.Errorf("PolyManager handleDepositEvents - failed to commit header err: %v", err)
		return false
	}

	return true
}

func (pm *PolyManager) selectSender() *ElrondSender {
	maxIndex := len(pm.senders)

	idx := rand.Intn(maxIndex)

	return pm.senders[idx]
}
