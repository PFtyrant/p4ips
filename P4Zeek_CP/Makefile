ifndef SDE_INSTALL
$(error SDE_INSTALL is not set)
endif


ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CP_SRC_DIR:=$(ROOT_DIR)/src
OUT_DIR:=$(ROOT_DIR)/build
P4_PROG = P4Zeek
ARCH = tofino
SOURCE = P4Zeek.cpp

CC = g++
CFLAGS = -DSDE_INSTALL=\"$(SDE_INSTALL)\" \
-I $(SDE_INSTALL)/include \
-I $(SDE)/pkgsrc/bf-drivers/src/bf_rt

# -I $(SDE)/pkgsrc/bf-drivers/include \
# pd rpc lib, back-up
# -I $(SDE_INSTALL)/include/$(ARCH)/pdfixed \
# -I $(SDE_INSTALL)/include/$(ARCH)pd/$(P4_PROG)\

BF_LIBS = -ldriver \
-lbfutils \
-lbfsys \
-lpcap

# bf lib back-up
#  -lavago \

LDFLAGS = -Wl,-rpath,$(SDE_INSTALL)/lib

LDLIBS = -L$(SDE_INSTALL)/lib
LDLIBS += -Wl,--start-group $(BF_LIBS) -Wl,--end-group
LDLIBS += -lm -pthread -lstdc++ -ldl -levent -lthrift -lpthread

all: clean copy $(P4_PROG)_cp

$(P4_PROG)_cp: $(CP_SRC_DIR)/$(SOURCE)
	$(CC) $(CFLAGS) $^ -o $(OUT_DIR)/$@ $(LDLIBS) $(LDFLAGS)

copy:
	@mkdir -p build
	@cp -r ./cmd ./cnn ./build

clean:
	@rm -rf build 
