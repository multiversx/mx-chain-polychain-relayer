package tools

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	logger "github.com/ElrondNetwork/elrond-go-logger"
)

var log = logger.GetOrCreate("process")

type RestClient struct {
	Addr       string
	restClient *http.Client
}

func NewRestClient() *RestClient {
	return &RestClient{
		restClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false,
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: time.Second * 300,
		},
	}
}

// CallGetRestEndPoint calls an external end point (sends a request on a node)
func (bp *RestClient) CallGetRestEndPoint(
	address string,
	url string,
	value interface{},
) (int, error) {
	req, err := http.NewRequest("GET", address+"/"+url, nil)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "userAgent")

	resp, err := bp.restClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			return http.StatusRequestTimeout, err
		}

		return http.StatusNotFound, err
	}

	defer func() {
		errNotCritical := resp.Body.Close()
		if errNotCritical != nil {
			log.Warn("base process GET: close body", "error", errNotCritical.Error())
		}
	}()

	err = json.NewDecoder(resp.Body).Decode(value)
	if err != nil {
		return 0, err
	}

	responseStatusCode := resp.StatusCode
	if responseStatusCode == http.StatusOK { // everything ok, return status ok and the expected response
		return responseStatusCode, nil
	}

	// status response not ok, return the error
	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return responseStatusCode, err
	}

	return responseStatusCode, errors.New(string(responseBytes))
}

func (bp *RestClient) CallPostRestEndPoint(
	address string,
	path string,
	data interface{},
	response interface{},
) (int, error) {
	buff, err := json.Marshal(data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	req, err := http.NewRequest("POST", address+"/"+path, bytes.NewReader(buff))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "userAgent")

	resp, err := bp.restClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			return http.StatusRequestTimeout, err
		}

		return http.StatusNotFound, err
	}

	defer func() {
		errNotCritical := resp.Body.Close()
		if errNotCritical != nil {
			log.Warn("base process POST: close body", "error", errNotCritical.Error())
		}
	}()

	responseStatusCode := resp.StatusCode
	if responseStatusCode == http.StatusOK { // everything ok, return status ok and the expected response
		return responseStatusCode, json.NewDecoder(resp.Body).Decode(response)
	}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return 0, err
	}

	// status response not ok, return the error
	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return responseStatusCode, err
	}

	return responseStatusCode, errors.New(string(responseBytes))
}

func isTimeoutError(err error) bool {
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return true
	}

	return false
}
