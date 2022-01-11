while getopts t:f:v:i:p: flag
do
	case "${flag}" in
		t) ARCHTECTURE=${OPTARG};;
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
		-DTOFINO2:BOOL=$2 \
		-DP4_NAME=$P4FILENAME \
		-DP4_PATH=$P4FILEPATH/$P4FILENAME.p4 \
		-DP4FLAGS="$INCLUDE_STR --verbose $VERBOSE --parser-timing-reports --create-graphs --display-power-budget"
}

if [ -z "$ARCHTECTURE" ] || [ $ARCHTECTURE -eq 1 ]; then
        do_config OFF
elif [ $ARCHTECTURE -eq 2 ]; then
        do_config ON
fi

#-DP4PPFLAGS="-Xp4c='--disable-power-check'" \
