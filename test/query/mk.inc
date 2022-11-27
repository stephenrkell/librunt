LDFLAGS += -Wl,-rpath,$(LIBRUNT_LIB_DIR)
LDLIBS += -lrunt
#export LD_PRELOAD := $(LIBRUNT)/lib/librunt_preload.so
