LIBSGXSTEP_DIR       = /home/thomas/kuleuven/thesis/sgx-step
LIBSGXSTEP           = $(LIBSGXSTEP_DIR)/libsgxstep

#ENCLAVE_D            = ../enclave-examples/enclave-buffer
ENCLAVE_D            = ../enclave-examples/002-sgx-inc-secret
#ENCLAVE_D            = ../enclave-examples/004-sgx-secstr
#ENCLAVE_D            = ../enclave-examples/005-sgx-rsa
#ENCLAVE_D            = ../enclave-examples/enclave-edger8r
ENCLAVE              = $(ENCLAVE_D)/Enclave
SUBDIRS              = $(ENCLAVE) $(LIBSGXSTEP)

CC                   = gcc
AS                   = gcc
LD                   = gcc

CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables \
                       -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0
INCLUDE              = -I$(SGX_SDK)/include/  -I../common/ -I$(LIBSGXSTEP_DIR) -I$(ENCLAVE_D)
LDFLAGS             += -lencl_proxy -lsgx_urts -lsgx-step \
                       -lsgx_uae_service -pthread $(SUBDIRS:%=-L %) -L$(SGX_SDK)/lib64/

SOURCES              = $(shell ls *.c ../common/*.c) $(ENCLAVE_D)/plug.c
OBJECTS              = $(SOURCES:.c=.o)
OUTPUT               = "run"

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)





.SILENT:
all: $(OUTPUT)
	
run: clean all
	./$(OUTPUT)

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT) 
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT) 

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(INCLUDE) -c $< -o $@

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)

$(BUILDDIRS):
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS):
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)
