.PHONY: all, install, clean  

TARGET := aes  

HDRS +=

CSRCS += ./aes_cbc.c \
		./aes_cfb.c \
		./aes_core.c \
		./aes_ctr.c \
		./aes_ecb.c \
		./aes_ofb.c \
		./test-aes.c \
	
CPPSRCS +=  

OBJSDIR =./build
OBJS := $(patsubst %.cpp, $(OBJSDIR)/%.o, $(CPPSRCS))  
OBJS += $(patsubst %.c, $(OBJSDIR)/%.o, $(CSRCS))  


INCDIR += -I./  
CFLAGS += -DDEBUG -Wall -g  
LDFLAGS += -L./ -ltag -ltag_c  



CC := gcc  
CXX := g++  

all: ${TARGET}  
${TARGET} : $(OBJS)  
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

install:  
	cp -rf ${TARGET} /usr/local/bin  

clean:  
	rm -rf ${OBJSDIR}  
	rm -rf ${TARGET}  
