# RLN - RGB Lightning Node

RGB-enabled LN node daemon ported from [rgb-lightning-sample], which is based
on [ldk-sample].

The node enables the possibility to create payment channels containing assets
issued using the RGB protocol, as well as routing RGB asset denominated
payments across multiple channels, given that they all possess the necessary
liquidity. In this way, RGB assets can be transferred with the same user
experience and security assumptions of regular Bitcoin Lightning Network
payments. This is achieved by adding to each lightning commitment transaction a
dedicated extra output containing the anchor to the RGB state transition.

More context on how RGB works on the Lightning Network can be found
[here](https://docs.rgb.info/lightning-network-compatibility).

The RGB functionality for now can be tested only in regtest or testnet
environments, but an advanced user may be able to apply changes in order to use
it also on other networks.
Please be careful, this software is early alpha, we do not take any
responsibility for loss of funds or any other issue you may encounter.

Also note that [rust-lightning] has been changed in order to support RGB
channels,
[here](https://github.com/RGB-Tools/rust-lightning/compare/v0.0.125...rgb)
a comparison with `v0.0.125`, the version we applied the changes to.

## Install

Clone the project, including (shallow) submodules:
```sh
git clone https://github.com/RGB-Tools/rgb-lightning-node --recurse-submodules --shallow-submodules
```

Then, from the project root, install the `rgb-lightning-node` binary by
running:
```sh
cargo install --locked --debug --path .
```

## Run

In order to operate, the node will need:
- a bitcoind node
- an indexer instance (electrum or esplora)
- an [RGB proxy server] instance

Once services are running, daemons can be started.
Each daemon needs to be started in a separate shell with `rgb-lightning-node`,
specifying:
- bitcoind user, password, host and port
- node data directory
- node listening port
- LN peer listening port
- network

### Regtest

To easily start the required services on a regtest network, run:
```sh
./regtest.sh start
```

This command will create the directories needed by the services, start the
docker containers and mine some blocks. The test environment will always start
in a clean state, taking down previous running services (if any) and
re-creating data directories.

Here's an example of how to start three regtest nodes, each one using the
shared regtest services provided by docker compose:
```sh
# 1st shell
rgb-lightning-node dataldk0/ --daemon-listening-port 3001 \
    --ldk-peer-listening-port 9735 --network regtest

# 2nd shell
rgb-lightning-node dataldk1/ --daemon-listening-port 3002 \
    --ldk-peer-listening-port 9736 --network regtest

# 3rd shell
rgb-lightning-node dataldk2/ --daemon-listening-port 3003 \
    --ldk-peer-listening-port 9737 --network regtest
```

To send some bitcoins to a node, first get a bitcoin address with the POST
`/address` API, then run:
```sh
./regtest.sh sendtoaddress <address> <amount>
```

To mine, run:
```sh
./regtest.sh mine <blocks>
```

To stop running services and to cleanup data directories, run:
```sh
./regtest.sh stop
```

For more info about regtest utility commands, run:
```sh
./regtest.sh -h
```

When unlocking regtest nodes use the following local services:
- bitcoind_rpc_username: user
- bitcoind_rpc_password: password
- bitcoind_rpc_host: localhost
- bitcoind_rpc_port: 18433
- indexer_url: 127.0.0.1:50001
- proxy_endpoint: rpc://127.0.0.1:3000/json-rpc

### Testnet

When running the node on the testnet network the docker services are not needed
because the node will use some public services.

Here's an example of how to start three testnet nodes, each one using the
external testnet services:

```sh
# 1st shell
rgb-lightning-node dataldk0/ --daemon-listening-port 3001 \
    --ldk-peer-listening-port 9735 --network testnet

# 2nd shell
rgb-lightning-node dataldk1/ --daemon-listening-port 3002 \
    --ldk-peer-listening-port 9736 --network testnet

# 3rd shell
rgb-lightning-node dataldk2/ --daemon-listening-port 3003 \
    --ldk-peer-listening-port 9737 --network testnet
```

When unlocking testnet nodes you can use the following services:
- bitcoind_rpc_username: user
- bitcoind_rpc_username: password
- bitcoind_rpc_host: electrum.iriswallet.com
- bitcoind_rpc_port: 18332
- indexer_url: ssl://electrum.iriswallet.com:50013
- proxy_endpoint: rpcs://proxy.iriswallet.com/0.2/json-rpc

## Use

Once daemons are running, they can be operated via REST JSON APIs.

For example, using curl:
```bash
curl -X POST -H "Content-type: application/json" \
    -d '{"ticker": "USDT", "name": "Tether", "amounts": [666], "precision": 0}' \
    http://localhost:3001/issueasset
```

The node currently exposes the following APIs:
- `/address` (POST)
- `/assetbalance` (POST)
- `/assetidfromhexbytes` (POST)
- `/assetidtohexbytes` (POST)
- `/assetmetadata` (POST)
- `/backup` (POST)
- `/btcbalance` (POST)
- `/changepassword` (POST)
- `/checkindexerurl` (POST)
- `/checkproxyendpoint` (POST)
- `/closechannel` (POST)
- `/connectpeer` (POST)
- `/createutxos` (POST)
- `/decodelninvoice` (POST)
- `/decodergbinvoice` (POST)
- `/disconnectpeer` (POST)
- `/estimatefee` (POST)
- `/failtransfers` (POST)
- `/getassetmedia` (POST)
- `/getchannelid` (POST)
- `/getpayment` (POST)
- `/getswap` (POST)
- `/init` (POST)
- `/invoicestatus` (POST)
- `/issueassetcfa` (POST)
- `/issueassetnia` (POST)
- `/issueassetuda` (POST)
- `/keysend` (POST)
- `/listassets` (POST)
- `/listchannels` (GET)
- `/listpayments` (GET)
- `/listpeers` (GET)
- `/listswaps` (GET)
- `/listtransactions` (POST)
- `/listtransfers` (POST)
- `/listunspents` (POST)
- `/lninvoice` (POST)
- `/lock` (POST)
- `/makerexecute` (POST)
- `/makerinit` (POST)
- `/networkinfo` (GET)
- `/nodeinfo` (GET)
- `/openchannel` (POST)
- `/postassetmedia` (POST)
- `/refreshtransfers` (POST)
- `/restore` (POST)
- `/rgbinvoice` (POST)
- `/sendasset` (POST)
- `/sendbtc` (POST)
- `/sendonionmessage` (POST)
- `/sendpayment` (POST)
- `/shutdown` (POST)
- `/signmessage` (POST)
- `/sync` (POST)
- `/taker` (POST)
- `/unlock` (POST)

To get more details about the available APIs see the [OpenAPI specification].
A Swagger UI for the `master` branch is generated from the specification and
available at https://rgb-tools.github.io/rgb-lightning-node.
Otherwise you can can browse a local copy exposing it with a web server.  As a
quick example, from the project root you can run:
```bash
python3 -m http.server
```
Then point a browser to `http://localhost:8000`.

If a daemon is running on your machine on one of the example ports
given above, you can even call the APIs directly from the Swagger UI.

To stop the daemon, exit with the `/shutdown` API (or press `Ctrl+C`).

## Test

Tests for a few scenarios using the regtest network are included. The same
services and data directories as the regtest.sh script are used, so the two
cannot run at the same time.

Tests can be executed with:
```sh
cargo test
```


[RGB proxy server]: https://github.com/RGB-Tools/rgb-proxy-server
[ldk-sample]: https://github.com/lightningdevkit/ldk-sample
[OpenAPI specification]: /openapi.yaml
[rgb-lightning-sample]: https://github.com/RGB-Tools/rgb-lightning-sample
[rust-lightning]: https://github.com/lightningdevkit/rust-lightning
