module github.com/ElrondNetwork/elrond-polychain-relayer

go 1.15

require (
	github.com/ElrondNetwork/elrond-go-core v1.1.0
	github.com/ElrondNetwork/elrond-go-crypto v1.0.1
	github.com/ElrondNetwork/elrond-go-logger v1.0.5
	github.com/ElrondNetwork/elrond-sdk-erdgo v1.0.3
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/cmars/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/ontio/ontology v1.11.0
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/poly v0.0.0-20200715030435-4f1d1a0adb44
	github.com/polynetwork/poly-go-sdk v0.0.0-20200817120957-365691ad3493
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.5
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
)

replace github.com/ElrondNetwork/arwen-wasm-vm/v1_2 v1.2.30 => github.com/ElrondNetwork/arwen-wasm-vm v1.2.30

replace github.com/ElrondNetwork/arwen-wasm-vm/v1_3 v1.3.30 => github.com/ElrondNetwork/arwen-wasm-vm v1.3.30

replace github.com/ElrondNetwork/arwen-wasm-vm/v1_4 v1.4.14 => github.com/ElrondNetwork/arwen-wasm-vm v1.4.14

replace github.com/ElrondNetwork/arwen-wasm-vm/v1_3 v1.3.19 => github.com/ElrondNetwork/arwen-wasm-vm v1.3.19
