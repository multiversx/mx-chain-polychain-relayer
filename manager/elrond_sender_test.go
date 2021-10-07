package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ElrondNetwork/elrond-polychain-relayer/config"
	"github.com/ElrondNetwork/elrond-polychain-relayer/tools"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/interactors"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	sdk "github.com/polynetwork/poly-go-sdk"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
)

func TestVerifySigs(t *testing.T) {
	polySdk := sdk.NewPolySdk()

	servConfig := config.NewServiceConfig("./testing/tconfig.json")
	if servConfig == nil {
		return
	}

	_ = SetUpPoly(polySdk, servConfig.PolyConfig.RestURL)
	currHeight := uint32(60000) // change epoch at 60000 rounds
	headerEpochChange, _ := polySdk.GetHeaderByHeight(currHeight)

	info := &vconfig.VbftBlockInfo{}

	_ = json.Unmarshal(headerEpochChange.ConsensusPayload, info)

	//bookkepers
	var bookkeepers []keypair.PublicKey
	var keys []byte
	for _, peer := range info.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		raw := tools.GetNoCompressKey(key)
		key, _ = keypair.DeserializePublicKey(raw)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)

	currHeight = uint32(120000)
	header, _ := polySdk.GetHeaderByHeight(currHeight)

	sigs := make([]*signature.Signature, 0, 0)
	for _, sig := range header.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		signa, _ := signature.Deserialize(temp)
		sigs = append(sigs, signa)
	}

	sol := 0
	i := 0
	j := 0
	var test []byte
	for _, sig := range sigs {
		j = 0
		fmt.Println("\nNEW SIG")
		for _, pk := range bookkeepers {
			hash := header.Hash()
			hashArr := hash.ToArray()
			rawKey := tools.GetNoCompressKey(pk)
			keys = append(keys, rawKey...)
			fmt.Println("key: " + hex.EncodeToString(rawKey))
			if signature.Verify(pk, hashArr[:], sig) {

				sigRaw, _ := signature.Serialize(sig)
				sigRaw, _ = ConvertToErdCompatible(sigRaw)

				hashRaw := sha256.Sum256(header.GetMessage())

				fmt.Println("Sig len:" + strconv.Itoa(len(sigRaw)) + " Sig index: " + strconv.Itoa(i) + " " + hex.EncodeToString(sigRaw[:]))
				fmt.Println("pk len:" + strconv.Itoa(len(rawKey)) + " Pk index: " + strconv.Itoa(j) + " " + hex.EncodeToString(rawKey[:]))
				fmt.Println("hash len:" + strconv.Itoa(len(hashRaw)) + " " + hex.EncodeToString(hashRaw[:]))

				err := tools.VerifySecp256k1(rawKey[2:], hashRaw[:], sigRaw)
				if err == nil {
					if hex.EncodeToString(rawKey) == "042092e34e0176dccf8abb496b833d591d25533469b3caf0e279b9742955dd8fc3899a042cd338e82698b5284720f85b309f2b711c05cb37836488371741168da6" || hex.EncodeToString(rawKey) == "047bd771e68adb88398282e21a8b03c12f64c2351ea49a2ba06a0327c83b239ca9420cf3852f7991d2a53afd008d1f6c356294b83aeeb4aad769f8c95ffeb4d5ac" {
						test = append(sigRaw, test...)
					}
					fmt.Println("valid" + "\n")
				} else {
					fmt.Println("Invalid" + "\n")
				}

				sol++
			}
			j++
		}
		i++
	}

	fmt.Println("number of sigs: " + strconv.Itoa(len(sigs)))
	fmt.Println("number of bookkeepers: " + strconv.Itoa(len(bookkeepers)))
	fmt.Println("number of valid sigs: " + strconv.Itoa(sol))

	fmt.Println("combined sigs " + hex.EncodeToString(test))

	assert.True(t, sol >= len(bookkeepers)*2/3)

}

func TestElrondSender_getRouter(t *testing.T) {
	servConfig := config.NewServiceConfig("./testing/tconfig.json")
	if servConfig == nil {
		return
	}
	es := createSender(servConfig)
	res := es.getRouter()

	assert.NotEmpty(t, res)
	router, err := strconv.ParseInt(res, 10, 64)
	assert.Nil(t, err)
	assert.True(t, router < es.routineNum)

}

func createSender(cfg *config.ServiceConfig) *ElrondSender {

	keysStoreFiles, err := tools.GetAllKeyStoreFiles(cfg.ElrondConfig.KeyStorePath)
	if err != nil {
		return nil
	}

	keysStoreFilesPW := cfg.ElrondConfig.KeyStorePwdSet

	bech32Addr, errGetAddr := tools.GetBech32AddressFromKeystoreFile(keysStoreFiles[0])
	if errGetAddr != nil {
		return nil
	}

	wallet := interactors.NewWallet()
	privKey, errLoad := wallet.LoadPrivateKeyFromJsonFile(keysStoreFiles[0], keysStoreFilesPW[bech32Addr])
	if errLoad != nil {
		return nil
	}

	sender, _ := NewElrondSender(privKey, cfg)

	return sender
}
