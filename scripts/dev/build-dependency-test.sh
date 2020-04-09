#!/bin/bash

set -e
set -o pipefail

CMD=${0##*/}

# Set up for tmp files and a trap to remove them
TMP=$(mktemp -d /tmp/$CMD.XXX)
TRAP_SIGS="INT TERM EXIT"
trap trap_proc $TRAP_SIGS
trap_proc () {
    trap "" $TRAP_SIGS
    /bin/rm -fr "$TMP"
}

fatal () {
    set +e +u +x
    echo "" 1>&2
    while (( $# > 0 )); do
        echo "$1"
        shift
    done 1>&2
    echo "" 1>&2
    exit 1
}

syntax () {
    fatal "$@" "Use -h for help"
}

help () {
    cat <<EOF
Usage: $CMD <build_type> [options]
Build type is one of: debug, release, relassert, etc.
Options:
    -h   // show help

This command creates a set of shell scripts that can
be used to test and debug build dependency errors.
EOF
}

BUILD_TYPE=

while getopts ":hfv:" c ; do
	case $c in
	h) help; exit 0;;
        \?) syntax "invalid option $OPTARG";;
        \:) syntax "option $OPTARG requires an argument";;
	esac
done

shift $(expr $OPTIND - 1)

[[ $# -lt 1 ]] && syntax "insufficient arguments for mandatory parameters"
[[ $# -gt 1 ]] && syntax "extraneous arguments"

BUILD_TYPE=$1

[[ "$BUILD_TYPE" == "" ]] && syntax "Missing build type."

DEPTEST_TOP=/var/tmp/builds-$(id -un)/deptests

BUILD_DIR=$(make BTOPDIR="$DEPTEST_TOP" "$BUILD_TYPE" printq-BUILD_DIR) ||
    fatal "Verify that '$BUILD_TYPE' is a valid build type..."

DEPTEST_DIR=$BUILD_DIR.deptests
SCRIPT_DIR=$DEPTEST_DIR/scripts
LOG_DIR=$DEPTEST_DIR/logs

echo "Build type:  $BUILD_TYPE"
echo "Build dir:   $BUILD_DIR"
echo "Scripts:     $SCRIPT_DIR"
echo "Logs:        $LOG_DIR"
echo ""

set -x

rm -fr "$DEPTEST_DIR"
rm -fr "$BUILD_DIR"
rm -fr "$BUILD_DIR".orig

mkdir -p "$DEPTEST_DIR"
mkdir -p "$SCRIPT_DIR"
mkdir -p "$LOG_DIR"

make BTOPDIR="$DEPTEST_TOP" "$BUILD_TYPE" scrub config >& "$DEPTEST_DIR"/config.log ||
    fatal "Make config failed.  Check log file: $DEPTEST_DIR/config.log"

set +x
echo "Building test scripts..."

echo "#!/bin/bash" > $SCRIPT_DIR/runall.sh

make -C "$BUILD_DIR" help > $TMP/help1

awk '($1=="...") {target=$2; tag=$2; gsub(/\//,"-",tag); print(target, tag);}' < $TMP/help1 > $TMP/help2

while read target tag; do
    log=$LOG_DIR/$tag.log
    script=$SCRIPT_DIR/make.$tag.sh

    # Add to runall, with exceptions
    case "$tag" in

        # blocks waiting for user input
        (edit_cache);;

        # requires root access
        (install-local);;
        (install);;
        (install-strip);;

        # add to runall script
        (*) echo "$script" >> $SCRIPT_DIR/runall.sh;;
    esac

    cat >"$script" <<EOF
#!/bin/bash

echo "Target $target, log $log"
exec >$log 2>&1
touch $log.failed
set -e -x
rm -fr $BUILD_DIR
cp -a $BUILD_DIR.orig $BUILD_DIR
make -C $BUILD_DIR $target 
touch $log.success
rm -f $log.failed
EOF

done < $TMP/help2

chmod 755 "$SCRIPT_DIR"/*.sh
mv "$BUILD_DIR" "$BUILD_DIR".orig
ls -ld "$BUILD_DIR".orig "$SCRIPT_DIR" "$LOG_DIR"

cat <<EOF

Execute the following script to test each cmake target:

    $SCRIPT_DIR/runall.sh

It can take a long time (hours) because it builds each target from
scratch without use of 'make -j'.  After completion, the following
command will show you which commands failed:

    ls $LOG_DIR/*.failed
EOF

exit 0
