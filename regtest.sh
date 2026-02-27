#!/usr/bin/env bash
#
# utility script to run and command regtest services
#

name="./$(basename "$0")"

COMPOSE="docker compose"
if ! $COMPOSE >/dev/null; then
    echo "could not call docker compose (hint: install docker compose plugin)"
    exit 1
fi
BITCOIN_CLI="$COMPOSE exec -u blits bitcoind bitcoin-cli -regtest"
INITIAL_BLOCKS=103
TIMEOUT=100

_die () {
    echo "ERR: $*"
    exit 1
}

_is_port_bound() {
    local port=$1
    case "$(uname)" in
        "Linux")
            [ -n "$(ss -HOlnt "sport = :$port")" ] && return 0
            ;;
        "Darwin")
            lsof -i "tcp:${port}" -sTCP:LISTEN -t >/dev/null && return 0
            ;;
        *)
            _die "port check unsupported on this OS ($(uname))"
            ;;
    esac
    return 1
}

_wait_for_bitcoind() {
    # wait for bitcoind to be up
    start_time=$(date +%s)
    until $BITCOIN_CLI getblockcount >/dev/null 2>&1; do
        current_time=$(date +%s)
        if [ $((current_time - start_time)) -gt $TIMEOUT ]; then
            echo "Timeout waiting for bitcoind to start"
            $COMPOSE logs bitcoind
            exit 1
        fi
        sleep 1
    done
}

_wait_for_electrs() {
    # wait for electrs to have completed startup
    start_time=$(date +%s)
    until $COMPOSE logs electrs |grep -q 'finished full compaction'; do
        current_time=$(date +%s)
        if [ $((current_time - start_time)) -gt $TIMEOUT ]; then
            echo "Timeout waiting for electrs to start"
            $COMPOSE logs electrs
            exit 1
        fi
        sleep 1
    done
}

_start_services() {
    _stop_services

    mkdir -p data{core,index,ldk0,ldk1,ldk2}
    # see compose.yaml for the exposed ports
    EXPOSED_PORTS=(3000 50001)
    for port in "${EXPOSED_PORTS[@]}"; do
        if _is_port_bound "$port"; then
            _die "port $port is already bound, services can't be started"
        fi
    done
    $COMPOSE up -d bitcoind
    echo && echo "preparing bitcoind wallet"
    _wait_for_bitcoind
    $COMPOSE up -d electrs proxy
    $BITCOIN_CLI createwallet miner >/dev/null
    $BITCOIN_CLI -rpcwallet=miner -generate $INITIAL_BLOCKS >/dev/null
    echo "waiting for electrs to have completed startup"
    _wait_for_electrs
}

_stop_services() {
    $COMPOSE down -v --remove-orphans
    rm -rf data{core,index,ldk0,ldk1,ldk2}
}

_mine() {
    local num_blocks="$1"
    $BITCOIN_CLI -rpcwallet=miner -generate "$num_blocks" >/dev/null
}

_sendtoaddress() {
    local address="$1"
    local amount="$2"
    $BITCOIN_CLI sendtoaddress "$address" "$amount"
}

_help() {
    echo "$name [-h|--help]"
    echo "    show this help message"
    echo
    echo "$name start"
    echo "    stop services, clean up, start services,"
    echo "    wait for services to have completed startup,"
    echo "    create bitcoind wallet used for mining,"
    echo "    generate initial blocks"
    echo
    echo "$name stop"
    echo "    stop services and clean up"
    echo
    echo "$name mine <blocks>"
    echo "    mine the requested number of blocks"
    echo
    echo "$name sendtoaddress <address> <amount>"
    echo "    send the requested amount to the specified bitcoin address"
}

# cmdline arguments
[ -z "$1" ] && _help
case $1 in
    -h|--help)
        _help
        ;;
    start)
        _start_services
        ;;
    stop)
        _stop_services
        ;;
    mine)
        [ -n "$2" ] || _die "num blocks is required"
        _mine "$2"
        ;;
    sendtoaddress)
        [ -n "$2" ] || _die "address is required"
        [ -n "$3" ] || _die "amount is required"
        _sendtoaddress "$2" "$3"
        ;;
    *)
        _die "unsupported argument \"$1\""
        ;;
esac
