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

_die () {
    echo "ERR: $*"
    exit 1
}

_start_services() {
    _stop_services

    mkdir -p data{core,index,ldk0,ldk1,ldk2}
    # see compose.yaml for the exposed ports
    EXPOSED_PORTS=(3000 50001)
    for port in "${EXPOSED_PORTS[@]}"; do
        if [ -n "$(ss -HOlnt "sport = :$port")" ];then
            _die "port $port is already bound, services can't be started"
        fi
    done
    $COMPOSE up -d
    echo && echo "preparing bitcoind wallet"
    $BITCOIN_CLI createwallet miner >/dev/null
    $BITCOIN_CLI -rpcwallet=miner -generate $INITIAL_BLOCKS >/dev/null
    export HEIGHT=$INITIAL_BLOCKS
    # wait for electrs to have completed startup
    until $COMPOSE logs electrs |grep 'finished full compaction' >/dev/null; do
        sleep 1
    done
}

_stop_services() {
    $COMPOSE down --remove-orphans
    rm -rf data{core,index,ldk0,ldk1,ldk2}
}

_mine() {
    $BITCOIN_CLI -rpcwallet=miner -generate "$NUM_BLOCKS" >/dev/null
}

_sendtoaddress() {
    $BITCOIN_CLI sendtoaddress "$ADDRESS" "$AMOUNT"
}

_help() {
    echo "$name [-h|--help]"
    echo "    show this help message"
    echo
    echo "$name start"
    echo "    stop services, clean up, start services,"
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
    echo "    send to a bitcoin address"
}

# cmdline arguments
[ -z "$1" ] && _help
while [ -n "$1" ]; do
    case $1 in
        -h|--help)
            _help
            exit 0
            ;;
        start)
            start=1
            ;;
        stop)
            stop=1
            ;;
        mine)
            [ -n "$2" ] || _die "num blocks is required"
            NUM_BLOCKS="$2"
            mine=1
            shift
            ;;
        sendtoaddress)
            [ -n "$2" ] || _die "address is required"
            [ -n "$3" ] || _die "amount is required"
            ADDRESS="$2"
            AMOUNT="$3"
            sendtoaddress=1
            shift 2
            ;;
        *)
            _die "unsupported argument \"$1\""
            ;;
    esac
    shift
done

# start services if requested
[ "$start" = "1" ] && _start_services

# stop services if requested
if [ "$stop" = "1" ]; then
    _stop_services
fi

[ "$mine" = "1" ] && _mine

[ "$sendtoaddress" = "1" ] && _sendtoaddress

exit 0
