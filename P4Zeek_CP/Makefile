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
-I $(SDE_INSTALL)/include/$(ARCH)/pdfixed \
-I $(SDE_INSTALL)/include/$(ARCH)pd/$(P4_PROG)\
-I $(SDE)/pkgsrc/bf-drivers/include \
-I $(SDE)/pkgsrc/bf-drivers/src/bf_rt
# new add

BF_LIBS = -lavago \
-ldriver \
-lbfutils \
-lbfsys \
-lpcap

LDFLAGS = -Wl,-rpath,$(SDE_INSTALL)/lib
LDFLAGS += -Wl,-rpath,$(SDE_INSTALL)/lib/$(ARCH)pd/$(P4_PROG) 
LDLIBS = -L$(SDE_INSTALL)/lib -L$(SDE_INSTALL)/lib/$(ARCH)pd/$(P4_PROG)
LDLIBS += -Wl,--start-group $(BF_LIBS) -Wl,--end-group
LDLIBS += -lm -pthread -lstdc++ -ldl -levent -lthrift -lpthread

all: clean $(P4_PROG)_cp

$(P4_PROG)_cp: $(CP_SRC_DIR)/$(SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) $^ -o $(OUT_DIR)/$@ $(LDLIBS) $(LDFLAGS)

clean:
	@rm -rf build 