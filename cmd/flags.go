package cmd

import (
	"strings"

	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/urfave/cli"
)
const (
	defaultConfigFilePath = "./config.json"
)

var (
	LogLevelFlag = cli.UintFlag{
		Name:  "loglevel",
		Usage: "Set the log level to `<level>` (0~6). 0:Trace 1:Debug 2:Info 3:Warn 4:Error 5:Fatal 6:MaxLevel",
		Value: log.InfoLog,
	}

	ConfigPathFlag = cli.StringFlag{
		Name:  "cliconfig",
		Usage: "Server config file `<path>`",
		Value: defaultConfigFilePath,
	}
	LogDir = cli.StringFlag{
		Name:  "logdir",
		Usage: "log directory",
		Value: "./Log/",
	}
)

// GetFlagName deal with short flag, and return the flag name whether flag name have short name
func GetFlagName(flag cli.Flag) string {
	name := flag.GetName()
	if name == "" {
		return ""
	}

	return strings.TrimSpace(strings.Split(name, ",")[0])
}
