package manager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/interactors"
	"github.com/ontio/ontology-crypto/keypair"
	"math/big"
	"math/rand"
	"time"

	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/db"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/ontio/ontology-crypto/signature"
	polygosdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	polytypes "github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

const (
	SIGNATURE_LENGTH = 67
)

type PolyManager struct {
	syncedHeight uint32
	polySdk      *polygosdk.PolySdk
	exitChan     chan int
	db           *db.BoltDB
	cfg          *config.ServiceConfig

	elrondClient           *tools.ElrondClient
	crossChainManager      string
	crossChainManagerProxy string
	senders                []*ElrondSender
	pks                    []byte
}

func NewPolyManager(cfg *config.ServiceConfig, polySdk *polygosdk.PolySdk, elrondClient *tools.ElrondClient, boltDB *db.BoltDB) (*PolyManager, error) {
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

		wallet := interactors.NewWallet()
		privKey, errLoad := wallet.LoadPrivateKeyFromJsonFile(keyStore, keysStoreFilesPW[bech32Addr])
		if errLoad != nil {
			return nil, errLoad
		}

		sender, errSender := NewElrondSender(privKey, cfg)
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

func (pm *PolyManager) Stop() {
	pm.exitChan <- 1
	close(pm.exitChan)
	log.Infof("poly chain manager exit.")
}

func (pm *PolyManager) MonitorChain() {
	ret := pm.init()
	if ret == false {
		log.Errorf("MonitorChain - init failed\n")
	}
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
				blockHandleResult = pm.handleDepositEvents(pm.syncedHeight)
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

func (pm *PolyManager) IsNewEpoch(hdr *polytypes.Header, getRawBookkeepers func() []byte) (bool, []byte, error) {
	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, blkInfo); err != nil {
		return false, nil, fmt.Errorf("commitHeader - unmarshal blockInfo error: %s", err)
	}
	if hdr.NextBookkeeper == common.ADDRESS_EMPTY || blkInfo.NewChainConfig == nil {
		return false, nil, nil
	}

	rawKeepers := getRawBookkeepers()

	var bookkeepers []keypair.PublicKey
	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint64(uint64(len(bookkeepers)))
	for _, key := range bookkeepers {
		raw := tools.GetNoCompressKey(key)
		publickeys = append(publickeys, raw...)
		sink.WriteBytes(raw)
	}
	if bytes.Equal(rawKeepers, publickeys) {
		return false, nil, nil
	}
	return true, publickeys, nil
}

func (pm *PolyManager) init() bool {
	if pm.syncedHeight > 0 {
		log.Infof("PolyManager init - start height from flag: %d", pm.syncedHeight)
		return true
	}

	pm.syncedHeight = pm.db.GetPolyHeight()
	latestHeight := pm.getCurrentEpochStartHeight()
	if latestHeight > pm.syncedHeight {
		pm.syncedHeight = latestHeight
		log.Infof("PolyManager init - synced height from ECCM: %d", pm.syncedHeight)
		return true
	}

	log.Infof("PolyManager init - synced height from DB: %d", pm.syncedHeight)

	return true
}

func (pm *PolyManager) handleDepositEvents(height uint32) bool {

	sender := pm.selectSender()
	latestEpochStartHeight := pm.getCurrentEpochStartHeight()
	hdr, err := pm.polySdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("PolyManager handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}

	isCurr := latestEpochStartHeight < height+1
	isNewEpoch, pubkList, err := pm.IsNewEpoch(hdr, sender.GetBookkeepers)
	if err != nil {
		log.Errorf("falied to check isEpoch: %v", err)
		return false
	}

	anchor, hp := pm.getHeaderProofWithAnchor(isCurr, isNewEpoch, latestEpochStartHeight, height)

	if err := pm.verifyHeader(hdr, anchor, hp, isCurr); err != nil {
		log.Errorf("PolyManager handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
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
				isTarget = pm.filterEvents(param)
				if !isTarget {
					continue
				}
			}

			cnt++
			sender := pm.selectSender()
			log.Infof("sender %s is handling poly tx ( hash: %s, height: %d )",
				sender.address, event.TxHash, height)
			sender.CommitDepositEventsWithHeader(hdr, param, hp, anchor, event.TxHash, auditpath)

		}
	}

	if cnt == 0 && isNewEpoch && isCurr {
		sender := pm.selectSender()
		err = sender.CommitHeader(hdr, pubkList)
		if err != nil {
			log.Errorf("PolyManager failed to commit header err: %v", err)
			return false
		}
	}

	return true
}

func (pm *PolyManager) selectSender() *ElrondSender {
	var senders []*ElrondSender
	for _, v := range pm.senders {
		balance, err := v.GetBalance()
		if err != nil {
			log.Errorf("failed to get balance for %s: %v", v.address, err)
			continue
		}
		zero := big.NewInt(0)
		if res := balance.Cmp(zero); res == 1 {
			senders = append(senders, v)
		}
	}

	maxIndex := len(senders)
	if senders != nil && maxIndex > 0 {
		senderId := rand.Intn(maxIndex)
		return senders[senderId]
	}
	return pm.senders[0]
}

func (pm *PolyManager) getCurrentEpochStartHeight() uint32 {
	sender := pm.selectSender()

	epochStartHeight, err := sender.GetCurrentEpochStartHeight(pm.cfg.ElrondConfig.BlockHeaderSyncContract)
	if err != nil {
		log.Errorf("findLatestHeight - GetEpochStartHeight failed: %s", err.Error())
		return 0
	}

	return uint32(epochStartHeight)
}

func (pm *PolyManager) filterEvents(param *common2.ToMerkleValue) bool {
	isTarget := false
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
	return isTarget
}

func (pm *PolyManager) updatePubKeys(pubkList []byte) {
	if pubkList != nil {
		pm.pks = pubkList
	}
}

func (pm *PolyManager) verifySigs(hdr *polytypes.Header) bool {
	sigs := make([]*signature.Signature, 0, 0)
	for _, rawSig := range hdr.SigData {
		temp := make([]byte, len(rawSig))
		copy(temp, rawSig)
		sig, _ := signature.Deserialize(temp)
		sigs = append(sigs, sig)
	}

	nrOfValidSignatures := 0

	nrOfPks := len(pm.pks) / SIGNATURE_LENGTH
	for pkIndex := 0; pkIndex < nrOfPks; pkIndex++ {
		rawKey := pm.pks[pkIndex*SIGNATURE_LENGTH : (pkIndex+1)*SIGNATURE_LENGTH]
		for _, sig := range sigs {
			sigRaw, _ := signature.Serialize(sig)
			sigRaw, _ = ConvertToErdCompatible(sigRaw)
			hashRawHdr := sha256.Sum256(hdr.GetMessage())

			err := tools.VerifySecp256k1(rawKey[2:], hashRawHdr[:], sigRaw) // first 2 bytes represents key header
			if err == nil {
				nrOfValidSignatures++
				break
			}
		}
	}
	return nrOfValidSignatures == len(sigs) || len(pm.pks) == 0
}

func (pm *PolyManager) getHeaderProofWithAnchor(isCurr bool, isNewEpoch bool, latestEpochStartHeight uint32, height uint32) (*polytypes.Header, string) {
	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = pm.polySdk.GetHeaderByHeight(latestEpochStartHeight + 1)
		proof, _ := pm.polySdk.GetMerkleProof(height+1, latestEpochStartHeight+1)
		hp = proof.AuditPath
	} else if isNewEpoch {
		anchor, _ = pm.polySdk.GetHeaderByHeight(height + 2)
		proof, _ := pm.polySdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	return anchor, hp
}

func (pm *PolyManager) verifyHeader(hdr *polytypes.Header, anchor *polytypes.Header, hp string, isCurr bool) error {
	if isCurr {
		if headerIntegrity := pm.verifySigs(hdr); headerIntegrity == false {
			return errors.New(fmt.Sprintf("falied to check signatures for PolyNetwork Header: %v with nonce: %d", hdr.Hash(), hdr.Height))
		}
	} else {
		rawProof, _ := hex.DecodeString(hp)
		rawLeaf := tools.MerkleProve(rawProof, anchor.BlockRoot[:])
		headerHash := hdr.Hash()
		if rawLeaf == nil || bytes.Compare(rawLeaf, headerHash.ToArray()) != 0 {
			return errors.New(fmt.Sprintf("falied to check proof for PolyNetwork Header: %v with nonce: %d", hdr.Hash(), hdr.Height))
		}
	}
	return nil
}

// ConvertToErdCompatible 0x30 <length of whole message> <0x02> <length of R> <R> 0x2 <length of S> <S>
func ConvertToErdCompatible(sig []byte) ([]byte, error) {
	s, err := signature.Deserialize(sig)
	if err != nil {
		return nil, err
	}

	t, ok := s.Value.([]byte)
	if !ok {
		return nil, errors.New("invalid signature type")
	}

	if len(t) != 65 {
		return nil, errors.New("invalid signature length")
	}

	v := t[0]
	copy(t, t[1:])
	t[64] = v

	sol := make([]byte, 2)
	sol[0] = 0x30
	sol[1] = uint8(len(t)) + 3           // 4 for R and S length and 0x02 magic number
	sol = append(sol, 0x02)              // magic number
	sol = append(sol, 32)                // length of R
	sol = append(sol, t[:32]...)         // R
	sol = append(sol, 0x02)              // magic number
	sol = append(sol, 32)                // length of S
	sol = append(sol, t[32:len(t)-1]...) // S

	return sol[0:], nil
}
