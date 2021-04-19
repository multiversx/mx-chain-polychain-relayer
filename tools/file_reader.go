package tools

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func GetAllKeyStoreFiles(pathToFolder string) ([]string, error) {
	var files []string

	err := filepath.Walk(pathToFolder, func(pathToFile string, info os.FileInfo, err error) error {
		if pathToFolder == pathToFile {
			return nil
		}

		files = append(files, pathToFile)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

func GetBech32AddressFromKeystoreFile(pathToFile string) (string, error) {
	bytesValue, err := ioutil.ReadFile(pathToFile)
	if err != nil {
		return "", err
	}

	mapData := make(map[string]interface{})
	err = json.Unmarshal(bytesValue, &mapData)
	if err != nil {
		return "", err
	}

	bech32Addr, ok := mapData["bech32"]
	if !ok {
		return "", fmt.Errorf("cannot get bech32 address from key store file")
	}

	return fmt.Sprintf("%v", bech32Addr), nil
}
