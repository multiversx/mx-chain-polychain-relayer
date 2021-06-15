package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
)

const (
	ERD_MONITOR_INTERVAL  = 15 * time.Second
	POLY_MONITOR_INTERVAL = 1 * time.Second

	ERD_USEFUL_BLOCK_NUM     = 3
)

type ServiceConfig struct {
	PolyConfig      *PolyConfig
	ElrondConfig    *ElrondConfig
	BoltDbPath      string
	RoutineNum      int64
	TargetContracts []map[string]map[string][]uint64
}

type PolyConfig struct {
	ChainID                    int
	RestURL                    string
	EntranceContractAddress    string
	WalletFile                 string
	WalletPwd                  string
	PolyStartHeight            uint32
	PolyMonitorIntervalSeconds uint32
	OntUsefulBlocksNum         uint32
}

type ElrondConfig struct {
	ElrondChainID                       string
	ElrondTxVersion                     int
	ElrondBlockMonitorIntervalInSeconds int
	HyperblockPerBatch                  int
	ElrondForceHeight                   uint64
	RestURL                             string
	SideChainId                         uint64
	CrossChainManagerContract           string
	BlockHeaderSyncContract             string
	KeyStorePath                        string
	KeyStorePwdSet                      map[string]string
}

func ReadFile(fileName string) ([]byte, error) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: open file %s error %s", fileName, err)
	}
	defer func() {
		errClose := file.Close()
		if errClose != nil {
			log.Errorf("ReadFile: File %s close error %s", fileName, errClose)
		}
	}()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: ioutil.ReadAll %s error %s", fileName, err)
	}
	return data, nil
}

func NewServiceConfig(configFilePath string) *ServiceConfig {
	fileContent, err := ReadFile(configFilePath)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}
	servConfig := &ServiceConfig{}
	err = json.Unmarshal(fileContent, servConfig)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}

	return servConfig
}
