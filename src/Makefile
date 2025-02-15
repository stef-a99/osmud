# Copyright 2018 osMUD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Global target; when 'make' is run without arguments, this is what it should do
all: osmud

# These variables hold the name of the compilation tool, the compilation flags and the link flags
# We make use of these variables in the package manifest
CC = gcc
CFLAGS = -Wall -g -std=c99 -D_XOPEN_SOURCE=600 -DDEBUG
LDFLAGS = -ljson-c -lcurl -L/usr/lib/x86_64-linux-gnu/libmosquitto.so -pthread
CFLAGSCONF = `pkg-config --cflags glib-2.0`
LDFLAGSCONF = `pkg-config --libs glib-2.0`
RULES_DIR = rules
ODIR = odir

# This variable identifies all header files in the directory; we use it to create a dependency chain between the object files and the source files
# This approach will re-build your application whenever any header file changes. In a more complex application, such behavior is often undesirable
DEPS = $(wildcard *.h)
 
# This variable holds all source files to consider for the build; we use a wildcard to pick all files
SRC = $(wildcard *.c)
 
# This variable holds all object file names, constructed from the source file names using pattern substitution
OBJ = $(patsubst %.c, %.o, $(SRC))

version.c:
	 git rev-parse HEAD | awk ' BEGIN {print "#include \"version.h\""} {print "const char * build_git_sha = \"" $$0"\";"} END {}' > version.c
	 date | awk 'BEGIN {} {print "const char * build_git_time = \""$$0"\";"} END {} ' >> version.c 
 
# This rule builds individual object files, and depends on the corresponding C source files and the header files
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

#THIS BUILDS EVERY FILE IN IT. 
# To build 'helloworld', we depend on the object files, and link them all into a single executable using the compilation tool
# We use automatic variables to specify the final executable name 'helloworld', using '$@' and the '$^' will hold the names of all the
# dependencies of this rule
#osmud: $(OBJ)
#	$(CC) -o $@ $^ $(LDFLAGS)

openwrt.o:      openwrt/openwrt.c
	$(CC) $(CFLAGS) -c -o openwrt.o openwrt/openwrt.c

config.o:		etc/interface_conf_parser.c
	$(CC) $(CFLAGSCONF) etc/interface_conf_parser.c -c -o config.o

linux.o:     	config.o router-machine/linux.c
	$(CC) $(CFLAGS) $(CFLAGSCONF)  router-machine/linux.c -c -o linux.o

osmud:	 osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o openwrt.o mudparser.o mud_manager.o version.o
	$(CC) $(CFLAGS) $(LDFLAGS) osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o openwrt.o mudparser.o mud_manager.o version.o x509_mode.o -o osmud -ljson-c -lcurl -pthread -lmosquitto

osmud-generic:	 osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o config.o linux.o mudparser.o mud_manager.o version.o
	@ mkdir -p $(RULES_DIR)
	$(CC) $(CFLAGS) $(CFLAGSCONF) $(LDFLAGS)  osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o config.o linux.o mudparser.o mud_manager.o version.o x509_mode.o -o osmud -ljson-c -lcurl -lmosquitto -pthread $(LDFLAGSCONF)
 
# To clean build artifacts, we specify a 'clean' rule, and use PHONY to indicate that this rule never matches with a potential file in the directory
.PHONY: clean
 
clean:
	rm -f osmud *.o version.c
