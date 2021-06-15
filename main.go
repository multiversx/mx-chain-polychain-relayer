package main

import (
	"fmt"
	"github.com/ElrondNetwork/elrond-polychain-relayer/cmd"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/db"
	"github.com/ElrondNetwork/elrond-polychain-relayer/log"
	"github.com/ElrondNetwork/elrond-polychain-relayer/manager"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/urfave/cli"
)


func setupApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "Elrond relayer Service"
	app.Action = startServer
	app.Version = "v1.0.0"
	app.Copyright = "Copyright in 2021 The Elrond Network"
	app.Flags = []cli.Flag{
		cmd.LogLevelFlag,
		cmd.ConfigPathFlag,
		cmd.LogDir,

	}
	app.Commands = []cli.Command{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}
	return app
}

func startServer(ctx *cli.Context) {
	logLevel := ctx.GlobalInt(cmd.GetFlagName(cmd.LogLevelFlag))

	ld := ctx.GlobalString(cmd.GetFlagName(cmd.LogDir))
	log.InitLog(logLevel, ld, log.Stdout)

	configPath := ctx.GlobalString(cmd.GetFlagName(cmd.ConfigPathFlag))

	servConfig := config.NewServiceConfig(configPath)
	if servConfig == nil {
		log.Errorf("startServer - create config failed!")
		return
	}

	polySdk := sdk.NewPolySdk()
	err := setUpPoly(polySdk, servConfig.PolyConfig.RestURL)
	/*if err != nil {
		log.Errorf("startServer - failed to setup poly sdk: %v", err)
		return
	}*/

	elrondClient := tools.NewElrondClient(servConfig.ElrondConfig.RestURL)

	var boltDB *db.BoltDB
	if servConfig.BoltDbPath == "" {
		boltDB, err = db.NewBoltDB("boltdb")
	} else {
		boltDB, err = db.NewBoltDB(servConfig.BoltDbPath)
	}
	if err != nil {
		log.Fatalf("db.NewWaitingDB error:%s", err)
		return
	}

	//initPolyManager(servConfig, polySdk, elrondClient, boltDB)
	initElrondManager(servConfig, polySdk, elrondClient, boltDB)

	waitToExit()
}

func initElrondManager(servConfig *config.ServiceConfig, polysdk *sdk.PolySdk, elrondClient *tools.ElrondClient, boltDB *db.BoltDB) {
	elrondManager, err := manager.NewElrondSyncManager(servConfig, polysdk, elrondClient, boltDB)
	if err != nil {
		log.Error("initElrondManager - elrond service start err: %s", err.Error())
		return
	}

	go elrondManager.MonitorChain()
	go elrondManager.MonitorDeposit()
	go elrondManager.CheckDeposit()
}

func initPolyManager(servConfig *config.ServiceConfig, polysdk *sdk.PolySdk, elrondClient *tools.ElrondClient, boltDB *db.BoltDB) {
	polyManager, err := manager.NewPolyManager(servConfig, polysdk, elrondClient, boltDB)
	if err != nil {
		log.Error("initPolyManager - poly service start err: %s", err.Error())
		return
	}

	go polyManager.MonitorChain()
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			log.Infof("waitToExit - Elrond relayer received exit signal:%v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}

func setUpPoly(poly *sdk.PolySdk, rpcAddr string) error {
	poly.NewRpcClient().SetAddress(rpcAddr)

	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}

	poly.SetChainId(hdr.ChainID)

	return nil
}

func main() {
	log.Infof("main - Elrond relayer starting...")
	if err := setupApp().Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
