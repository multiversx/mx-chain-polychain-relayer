package tools

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"path"

	"github.com/ElrondNetwork/elrond-proxy-go/data"
)

const (
	MetachainShardID   = uint32(4294967295)
	blocksPerEpochPoly = 60000
)

type ElrondClient struct {
	restUrl    string
	restClient *RestClient
}

func NewElrondClient(restUrl string) *ElrondClient {
	return &ElrondClient{
		restUrl:    restUrl,
		restClient: NewRestClient(),
	}
}

func (ec *ElrondClient) ExecuteQuery(vmRequest *data.VmValueRequest) (*data.VmValuesResponseData, error) {
	response := &data.ResponseVmValue{}
	pathAPI := path.Join("vm-values", "query")
	_, err := ec.restClient.CallPostRestEndPoint(ec.restUrl, pathAPI, vmRequest, &response)
	if err != nil {
		return nil, err
	}

	if response.Error != "" {
		return nil, fmt.Errorf("%s", response.Error)
	}

	return &response.Data, err
}

func (ec *ElrondClient) GetLatestHyperblockNonce() (uint64, error) {
	response := map[string]interface{}{}

	pathAPI := path.Join("network", "status", fmt.Sprintf("%d", MetachainShardID))
	_, err := ec.restClient.CallGetRestEndPoint(ec.restUrl, pathAPI, &response)
	if err != nil {
		return 0, err
	}

	nonce, ok := getNonceFromMetachainStatus(response["data"])
	if !ok {
		return 0, fmt.Errorf("cannot get latest hyberblock nonce")
	}

	return nonce, nil
}

func (ec *ElrondClient) GetHyperblockByNonce(nonce uint64) (*data.Hyperblock, error) {
	var hyperblockResponse data.HyperblockApiResponse

	pathAPI := path.Join("hyperblock", "by-nonce", fmt.Sprintf("%d", nonce))
	_, err := ec.restClient.CallGetRestEndPoint(ec.restUrl, pathAPI, &hyperblockResponse)
	if err != nil {
		return nil, err
	}

	if hyperblockResponse.Error != "" {
		return nil, fmt.Errorf(hyperblockResponse.Error)
	}

	return &hyperblockResponse.Data.Hyperblock, nil
}

func (ec *ElrondClient) GetCurrentEpochStartHeight(contractAddress string, chainID int) (uint64, error) {
	encodedChainID := hex.EncodeToString([]byte(fmt.Sprintf("%d", chainID)))

	vmRequest := &data.VmValueRequest{
		Address:    contractAddress,
		FuncName:   "currentHeight",
		CallerAddr: "",
		CallValue:  "",
		Args:       []string{encodedChainID},
	}

	response, err := ec.ExecuteQuery(vmRequest)
	if err != nil {
		return 0, err
	}

	bigIntValue := big.NewInt(0).SetBytes(response.Data.ReturnData[0])
	returnedHeight := bigIntValue.Uint64()

	startOfEpochHeight := returnedHeight % blocksPerEpochPoly * blocksPerEpochPoly

	return startOfEpochHeight, err
}

func (ec *ElrondClient) GetChainIDAndMinTxVersion() (string, uint32, error) {
	return "", 0, nil
}

func getNonceFromMetachainStatus(nodeStatusData interface{}) (uint64, bool) {
	metric, ok := getMetric(nodeStatusData, "erd_nonce")
	if !ok {
		return 0, false
	}

	return getUint(metric), true
}

func getMetric(nodeStatusData interface{}, metric string) (interface{}, bool) {
	metricsMapI, ok := nodeStatusData.(map[string]interface{})
	if !ok {
		return nil, false
	}

	metricsMap, ok := metricsMapI["status"]
	if !ok {
		return nil, false
	}

	metrics, ok := metricsMap.(map[string]interface{})
	if !ok {
		return nil, false
	}

	value, ok := metrics[metric]
	if !ok {
		return nil, false
	}

	return value, true
}

func getUint(value interface{}) uint64 {
	valueFloat, ok := value.(float64)
	if !ok {
		return 0
	}

	return uint64(valueFloat)
}
