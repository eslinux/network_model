# Straight forward Makefile to compile all examples in a row
APPNAME=ipsec_app


INCDIR= -I./ipsec/src/include \
		-I./ipsec/src/include/ipsec \
		-I./ipsec/src/include/netif \
		-I./ipsec/src/include/testing \
		-I./lwip/src/include \
		-I./lwip/src/include/ipv4 \
		-I./lwip/src/include/ipv6 \
		-I./lwip/src/include/lwip \
		-I./lwip/src/include/netif \
		-I./keil/echo/include \
		-I./keil/echo/include/arch \
		-I./ipsec/src/crypto/aes \
		-I./ipsec/src/crypto/hmac \


ifeq ('$(ARCH)', 'arm')
    BINDIR=./build/bin-arm
    OBJSDIR:=./build/objs-arm
else
    BINDIR=./build/bin
    OBJSDIR:=./build/objs
endif

HDRS+=  
		
CSRCS+= ./ipsec/src/core/ah.c \
		./ipsec/src/core/des.c \
		./ipsec/src/core/esp.c \
		./ipsec/src/core/ipsec.c \
		./ipsec/src/core/md5.c  \
		./ipsec/src/core/sa.c \
		./ipsec/src/core/sha1.c \
		./ipsec/src/core/util.c \
		./ipsec/src/crypto/aes/aes_cbc.c \
		./ipsec/src/crypto/aes/aes_cfb.c \
		./ipsec/src/crypto/aes/aes_core.c \
		./ipsec/src/crypto/aes/aes_ctr.c \
		./ipsec/src/crypto/aes/aes_ecb.c \
		./ipsec/src/crypto/aes/aes_ofb.c \
		./ipsec/src/crypto/hmac/hmac_sha2.c \
		./ipsec/src/crypto/hmac/sha2.c \
		./ipsec/src/testing/structural/sha1_test.c \
		./ipsec/src/testing/structural/sa_test.c \
		./ipsec/src/testing/structural/md5_test.c \
		./ipsec/src/testing/structural/esp_test.c \
		./ipsec/src/testing/structural/des_test.c \
		./ipsec/src/testing/structural/ah_test.c \
		./ipsec/src/testing/structural/util_test.c \
		./ipsec/src/testing/structural/main.c
		#./ipsec/src/netif/dumpdev.c \
		#./ipsec/src/netif/ipsecdev.c \

		
CPPSRCS+=
		

OBJS:= $(patsubst %.cpp, $(OBJSDIR)/%.o, $(CPPSRCS))
OBJS+= $(patsubst %.c, $(OBJSDIR)/%.o, $(CSRCS))

ifeq ('$(ARCH)', 'arm')
	CFLAGS += -DLINUX -DEGL_API_FB -DFREESCALE=1 -DDEBUG -D_DEBUG -D_GNU_SOURCE  -mfloat-abi=softfp -mfpu=neon -march=armv7-a -fPIC -O3 -fno-strict-aliasing -fno-optimize-sibling-calls  -g 
    CFLAGS += -DQT_BUILD -DOPENGL_ES_2_0 -DFBT_USE_GZ_FILE=1
    LDFLAGS += -L$(ROOTFS)/usr/lib -L$(ROOTFS)/usr/local/lib -mfloat-abi=softfp -mfpu=neon -march=armv7-a
	INCDIR += -I$(ROOTFS)/usr/include -I$(ROOTFS)/usr/local/include
	CC=$(CROSS_COMPILE)gcc
	CXX=$(CROSS_COMPILE)g++
else
	CFLAGS += -Wall -g
	LDFLAGS +=
	INCDIR +=
	INSTALLDIR:= /usr/sbin
	CC=gcc
	CXX=g++
endif


#MAKE
default: all
all: $(BINDIR)/$(APPNAME)
$(BINDIR)/$(APPNAME) : $(OBJS)
	@echo " [LINK] $@"
	@mkdir -p $(shell dirname $@)
	@$(CXX) $(OBJS) -o $@ $(LDFLAGS)
	
$(OBJSDIR)/%.o: %.c $(HDRS)
	@echo " [CC]   $@"
	@mkdir -p $(shell dirname $@)
	@$(CC) -c $< -o $@ $(CFLAGS) ${INCDIR}

$(OBJSDIR)/%.o: %.cpp $(HDRS)
	@echo " [CXX]  $@"
	@mkdir -p $(shell dirname $@)
	@$(CXX) -c $< -o $@ $(CFLAGS) ${INCDIR}
		
install: all
	cp -f $(BINDIR)/$(APPNAME) $(INSTALLDIR)
	mkdir -p $(INSTALL_IMAGES_DIR)
	
clean: 
	@echo "rm -rf $(BINDIR)/$(APPNAME) $(OBJS)"
	@rm -rf $(BINDIR)/$(APPNAME) $(OBJSDIR)
	
cleanall:
	@echo "rm -rf ./build/bin* ./build/objs*"
	@rm -rf ./build/bin* ./build/objs*
	
