#
# Common parameter parsing used by scripts in this directory
#  - Depending on bash 3 (or higher) syntax
#
# Author: Jesper Dangaaard Brouer <netoptimizer@brouer.com>
# License: GPLv2

function usage() {
    echo ""
    echo "Usage: $0 [-vh] --dev ethX"
    echo "  -d | --dev     : (\$DEV)        Interface/device (required)"
    echo "  -v | --verbose : (\$VERBOSE)    verbose"
    echo "  --remove       : (\$REMOVE)     Remove the TC rules"
    echo "  --dry-run      : (\$DRYRUN)     Dry-run only (echo tc commands)"
    echo "  -s | --stats   : (\$STATS_ONLY) Call TC statistics command"
    echo "  -l | --list    : (\$LIST)       List TC filter setup after setup"
    echo ""
}

# Using external program "getopt" to get --long-options
OPTIONS=$(getopt -o vshd:l \
    --long verbose,dry-run,remove,stats,list,help,dev: -- "$@")
if (( $? != 0 )); then
    usage
    err 2 "Error calling getopt"
fi
eval set -- "$OPTIONS"

##  --- Parse command line arguments / parameters ---
while true; do
    case "$1" in
        -d | --dev ) # device
          export DEV=$2
	  info "Device set to: DEV=$DEV" >&2
	  shift 2
          ;;
        -v | --verbose)
          export VERBOSE=yes
          # info "Verbose mode: VERBOSE=$VERBOSE" >&2
	  shift
          ;;
        --dry-run )
          export DRYRUN=yes
          export VERBOSE=yes
          info "Dry-run mode: enable VERBOSE and don't call TC" >&2
	  shift
          ;;
        --remove )
          export REMOVE=yes
	  shift
          ;;
        -s | --stats )
          export STATS_ONLY=yes
	  shift
          ;;
        -l | --list )
          export LIST=yes
	  shift
          ;;
	-- )
	  shift
	  break
	  ;;
        -h | --help )
          usage;
	  exit 0
	  ;;
	* )
	  shift
	  break
	  ;;
    esac
done

if [ -z "$DEV" ]; then
    usage
    err 2 "Please specify TC net_device"
fi