<h1 align=center> BSC Relayer </h1>

BSC Relayer is an important character of Poly cross-chain interactive protocol which is responsible for relaying cross-chain transaction from and to BSC.

## Build From Source

### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.14 or later

### Build

```shell
git clone https://github.com/polynetwork/bsc_relayer.git
cd bsc_relayer
go build -o bsc_relayer main.go
```

After building the source code successfully,  you should see the executable program `bsc_relayer`. 

### Build Docker Image

```
docker build -t polynetwork/bsc_relayer -f Dockerfile ./
```

This command will copy ./config.json to /app/config.json in the image. So you need to prepare config.json before running this command and you should start the eth-relayer in container basing on the configuration in /app/config.json.

## Run Relayer

Before you can run the relayer you will need to create a wallet file of PolyNetwork. After creation, you need to register it as a Relayer to Poly net and get consensus nodes approving your registeration. And then you can send transaction to Poly net and start relaying.

Before running, you need feed the configuration file `config.json`.

```
{
  "MultiChainConfig":{
    "RestURL":"http://poly_ip:20336", // address of Poly
    "EntranceContractAddress":"0300000000000000000000000000000000000000", // CrossChainManagerContractAddress on Poly. No need to change
    "WalletFile":"./wallet.dat", // your poly wallet
    "WalletPwd":"pwd" //password
  },
  "BSCConfig":{
    "SideChainId": 79, // bsc chainID
    "RestURL":"http://etheruem:port", // your bsc node 
    "ECCMContractAddress":"bsc_cross_chain_contract", 
    "ECCDContractAddress":"bsc_cross_chain_data_contract",
    "KeyStorePath": "./keystore", // path to store your bsc wallet
    "KeyStorePwdSet": { // password to protect your ethereum wallet
      "0xd12e...54ccacf91ca364d": "pwd1", // password for address "0xd12e...54ccacf91ca364d"
      "0xabb4...0aba7cf3ee3b953": "pwd2" // password for address "0xabb4...0aba7cf3ee3b953"
    },
    "BlockConfig": 15, // blocks to confirm a bsc tx
    "HeadersPerBatch": 200 // number of poly headers commited to ECCM in one transaction at most
  },
  "BoltDbPath": "./db", // DB path
  "RoutineNum": 64,
  "TargetContracts": [
    {
      "0xD8aE73e06552E...bcAbf9277a1aac99": { // your lockproxy hash
        "inbound": [6], // from which chain allowed
        "outbound": [6] // to which chain allowed
      }
    }
  ]
}
```

After that, make sure you already have a ethereum wallet with ETH. The wallet file is like `UTC--2020-08-17T03-44-00.191825735Z--0xd12e...54ccacf91ca364d` and you can use [geth](https://github.com/ethereum/go-ethereum) to create one( `./geth accounts add` ). Put it under `KeyStorePath`. You can create more than one wallet for relayer. Relayer will send transactions concurrently by different accounts.

Now, you can start relayer as follow: 

```shell
./eth_relayer --cliconfig=./config.json 
```

It will generate logs under `./Log` and check relayer status by view log file.

