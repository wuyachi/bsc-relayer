module github.com/polynetwork/bsc_relayer

go 1.15

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ethereum/go-ethereum v1.9.15
	github.com/ontio/ontology v1.12.0
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/eth-contracts v0.0.0-20200903021827-c9212e419943
	github.com/polynetwork/poly v0.0.0-20210108071928-86193b89e4e0
	github.com/polynetwork/poly-go-sdk v0.0.0-20200817120957-365691ad3493
	github.com/urfave/cli v1.22.5
	poly-bridge v0.0.0-20210112082403-a45d71989293
)

replace poly-bridge => github.com/polynetwork/poly-bridge v0.0.0-20210126083254-80335b53070a
