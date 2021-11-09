package tools

import (
	"errors"
	"fmt"
	txData "github.com/ElrondNetwork/elrond-go-core/data/transaction"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/blockchain"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/data"
	"path"
)

const (
	MetachainShardID = uint32(4294967295)
)

type ElrondClient struct {
	restUrl    string
	restClient *RestClient
}

type GetTransactionResponse struct {
	Data  GetTransactionResponseData `json:"data"`
	Error string                     `json:"error"`
	Code  string                     `json:"code"`
}

type GetTransactionResponseData struct {
	Transaction txData.ApiTransactionResult `json:"transaction"`
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

func (ec *ElrondClient) GetProof(nodeUrl string, blockRootHash string, address string, key string) (string, string, []string, error) {
	response := map[string]interface{}{}

	pathAPI := path.Join("proof", "root-hash", blockRootHash, "address", address, "key", key)
	_, err := ec.restClient.CallGetRestEndPoint(nodeUrl, pathAPI, &response)
	if err != nil {
		return "", "", nil, err
	}

	dataTrieProof, okDataTrieProof := getDataTrieProof(response["data"])
	dataTrieRootHash, okDataTrieRootHash := getDataTrieRootHash(response["data"])
	mainTrieProof, okMainTrieProof := getMainTreeProof(response["data"])

	if !(okDataTrieProof && okMainTrieProof && okDataTrieRootHash) {
		return "", "", nil, errors.New("error parse proofs")
	}

	return dataTrieProof, dataTrieRootHash, mainTrieProof, nil
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

func (ec *ElrondClient) GetHyperblockByNonce(nonce uint64) (*data.HyperBlock, error) {
	var hyperblockResponse data.HyperBlockResponse

	pathAPI := path.Join("hyperblock", "by-nonce", fmt.Sprintf("%d", nonce))
	_, err := ec.restClient.CallGetRestEndPoint(ec.restUrl, pathAPI, &hyperblockResponse)
	if err != nil {
		return nil, err
	}

	if hyperblockResponse.Error != "" {
		return nil, fmt.Errorf(hyperblockResponse.Error)
	}

	return &hyperblockResponse.Data.HyperBlock, nil
}

func (ec *ElrondClient) GetTransactionByHash(hash string) (*txData.ApiTransactionResult, error) {
	var transactionResponse GetTransactionResponse

	pathAPI := path.Join("transaction", hash, "?withResults=true")
	_, err := ec.restClient.CallGetRestEndPoint(ec.restUrl, pathAPI, &transactionResponse)
	if err != nil {
		return nil, err
	}

	return &transactionResponse.Data.Transaction, nil
}

func (ec *ElrondClient) GetTransactionsForHyperblock(nonce uint64) []data.TransactionOnNetwork {
	ep := blockchain.NewElrondProxy(ec.restUrl, nil)

	hyperblock, _ := ep.GetHyperBlockByNonce(nonce)

	transacrions := make([]data.TransactionOnNetwork, 0)

	for _, tx := range hyperblock.Transactions {
		if tx.Status == "success" {
			transacrions = append(transacrions, tx)
		}
	}

	return transacrions
}

func getNonceFromMetachainStatus(nodeStatusData interface{}) (uint64, bool) {
	metric, ok := getMetric(nodeStatusData, "erd_nonce")
	if !ok {
		return 0, false
	}

	return getUint(metric), true
}

func getDataTrieProof(nodeStatusData interface{}) (string, bool) {
	proofsMap, ok := nodeStatusData.(map[string]interface{})
	if !ok {
		return "", false
	}
	dataTrieProofs, ok := proofsMap["dataTrieProof"].([]string)
	if !ok {
		return "", false
	}

	return dataTrieProofs[0], true
}

func getDataTrieRootHash(nodeStatusData interface{}) (string, bool) {
	proofsMap, ok := nodeStatusData.(map[string]interface{})
	if !ok {
		return "", false
	}
	dataTrieRootHash, ok := proofsMap["dataTrieRootHash"].(string)
	if !ok {
		return "", false
	}

	return dataTrieRootHash, true
}

func getMainTreeProof(nodeStatusData interface{}) ([]string, bool) {
	proofsMap, ok := nodeStatusData.(map[string]interface{})
	if !ok {
		return nil, false
	}
	mainProof, ok := proofsMap["mainProof"].([]string)
	if !ok {
		return nil, false
	}

	return mainProof, true
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
