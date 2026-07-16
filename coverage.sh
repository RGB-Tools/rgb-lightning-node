#!/bin/bash -e
#
# script to run project tests and report code coverage
# uses llvm-cov (https://github.com/taiki-e/cargo-llvm-cov)

# only include lightning/src/rgb_utils from the rust-lightning submodule, as it
# contains all the RGB logic, while other changes with respect to upstream are
# short and only wire the logic in the appropriate places
#
# since llvm-cov's regex engine has no negative lookahead, this is expressed by
# listing rgb_utils' siblings
#
# note: these are in addition to common ignore patterns llvm-cov appends on its own
IGNORE_PATTERNS=(
    # the node's own test module
    'src/test($|/)'
    # all rust-lightning crates other than lightning
    'rust\-lightning/lightning\-'
    # other rust-lightning crates, possiblyrandom being a dependency of the lightning one
    'rust\-lightning/(no\-std\-check|possiblyrandom)/'
    # rust-lightning directories holding no crate code
    'rust\-lightning/(bench|ci|contrib|fuzz|ext\-functional\-test\-demo|msrv\-no\-dev\-deps\-check)/'
    # upstream modules of the lightning crate, i.e. all of them but rgb_utils
    'rust\-lightning/lightning/src/(blinded_path|chain|crypto|events|io|ln|offers|onion_message)($|/)'
    'rust\-lightning/lightning/src/(routing|sign|sync|util)($|/)'
    # root of the lightning crate
    'rust\-lightning/lightning/src/lib\.rs$'
)
IGNORE_PATTERN="$(IFS='|'; echo "${IGNORE_PATTERNS[*]}")"

LLVM_COV_OPTS=()
CI=0
CARGO_TEST_OPTS=("--" "--test-threads=1")
COV="cargo llvm-cov --ignore-filename-regex $IGNORE_PATTERN"

_die() {
    echo "err $*"
    exit 1
}

_tit() {
    echo
    echo "========================================"
    echo "$@"
    echo "========================================"
}

help() {
    echo "$NAME [-h|--help] [-t|--test] [--ci] [--ignore-run-fail] [--no-clean]"
    echo ""
    echo "options:"
    echo "    -h --help             show this help message"
    echo "    -t --test             only run these test(s)"
    echo "       --ci               run for the CI"
    echo "       --ignore-run-fail  keep running regardless of failure"
    echo "       --no-clean         don't cleanup before the run"
}

# cmdline arguments
while [ -n "$1" ]; do
    case $1 in
        -h | --help)
            help
            exit 0
            ;;
        -t | --test)
            CARGO_TEST_OPTS+=("$2")
            shift
            ;;
        --ci)
            CI=1
            ;;
        --ignore-run-fail)
            LLVM_COV_OPTS+=("$1")
            ;;
        --no-clean)
            LLVM_COV_OPTS+=("$1")
            ;;
        *)
            help
            _die "unsupported argument \"$1\""
            ;;
    esac
    shift
done

if [ "$CI" = 1 ]; then
    # CI version

    $COV "${LLVM_COV_OPTS[@]}" --lcov --output-path coverage.lcov "${CARGO_TEST_OPTS[@]}"
    exit 0
else
    # local version

    _tit "installing requirements"
    rustup component add llvm-tools-preview
    cargo install cargo-llvm-cov

    _tit "generating coverage report"
    $COV "${LLVM_COV_OPTS[@]}" --html "${CARGO_TEST_OPTS[@]}"

    # show html report location
    echo "generated html report: target/llvm-cov/html/index.html"
fi
