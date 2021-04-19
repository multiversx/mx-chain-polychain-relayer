package tools

import (
	"fmt"
	"testing"
)

func TestReadKeyStoreFiles(t *testing.T) {
	path := "../keys"

	files, err := GetAllKeyStoreFiles(path)
	fmt.Println(err)
	fmt.Println(files)
}
