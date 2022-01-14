# This script only suit for Tofino1

while getopts f:v:i:p: flag
do
	case "${flag}" in
		f) P4FILENAME=${OPTARG};;
		p) P4FILEPATH=${OPTARG};;
		v) VERBOSE=${OPTARG};;
		i) INCLUDE=${OPTARG};;
	esac
done


if [ -z "$VERBOSE" ]; then
	VERBOSE=2
fi

if [ -z "$INCLUDE" ]; then
	INCLUDE_STR=""
else
	INCLUDE_STR="-I $INCLUDE"
fi


do_config() {
	cmake $SDE/p4studio/ \
		-DCMAKE_INSTALL_PREFIX=$SDE_INSTALL \
		-DCMAKE_MODULE_PATH=$SDE/cmake \
		-DP4_NAME=$P4FILENAME \
		-DP4_PATH=$P4FILEPATH/$P4FILENAME.p4 \
		-DP4FLAGS="$INCLUDE_STR --verbose $VERBOSE --parser-timing-reports --create-graphs --display-power-budget"
}

do_config
