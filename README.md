# Elrond-Relayer

***


This program is still under developing!


Elrond Relayer is an important character of Poly cross-chain interactive protocol which is responsible for relaying cross-chain transaction from and to Elrond.

***

## Build From Source
***
### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.15 or later


### Build

```shell
git clone https://github.com/ElrondNetwork/elrond-polychain-relayer.git
cd elrond-polychain-relayer
go build -o elrond-polychain-relayer main.go
```

## Run Relayer

Before you can run the relayer you will need to create a wallet file of PolyNetwork. After creation, you need to register it as a Relayer to Poly net and get consensus nodes approving your registeration. And then you can send transaction to Poly net and start relaying.

After that, make sure you already have a Elrond wallet with EGLD.
- [Docs](https://docs.elrond.com/wallet/web-wallet/)

Before running, you need feed the configuration file `config.json`.

```
{
  "ElrondConfig": {
    "ElrondChainID": "",
    "ElrondTxVersion": 1,
    "ElrondBlockMonitorIntervalInSeconds": 6,
    "BlocksPerBatch": 15,
    "ElrondForceHeight": 0,
    "RestURL": "https://gateway.elrond.com",
    "SideChainID": 100,
    "CrossChainManagerContract": "",
    "BlockHeaderSyncContract": "",
    "KeyStorePath": "",
    "KeyStorePwdSet": {
      "": "",
    }
  },
  "PolyConfig": {
    "ChainID": 2,
    "RestURL": "http://beta1.poly.network:20336",
    "EntranceContractAddress": "0300000000000000000000000000000000000000",
    "OntUsefulBlocksNum": 1,
    "WalletFile": "./wallet.dat",
    "WalletPwd": "",
    "PolyStartHeight": 0,
    "PolyMonitorIntervalSeconds": 10
  },
  "BoltDbPath": "./db",
  "RoutineNum": 10,
  "TargetContracts": [
    {
      "0xD8aE73e06552E...bcAbf9277a1aac99": {
        "inbound": [6],
        "outbound": [6]
      }
    }
  ]
}
```

Now, you can start relayer as follow:

```shell
./elrond-polychain-relayer --cliconfig=./config.json 
```

It will generate logs under `./Log` and check relayer status by view log file.