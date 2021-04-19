package config

import (
	"fmt"
	"testing"
)

func TestReadConfig(t *testing.T) {
	t.Parallel()

	cfg := NewServiceConfig("../config.json")

	fmt.Println(cfg)
}
