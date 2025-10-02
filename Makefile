# Makefile for gsend and grec - File encryption/decryption utilities
#
# This Makefile builds two programs:
#   - gsend: encrypts and optionally transmits files
#   - grec: receives and decrypts files
#
# Both programs use OpenSSL libraries for cryptographic operations
#
# Usage:
#   make        - build both programs
#   make clean  - remove compiled binaries and object files
#   make all    - same as make

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

# Target executables
TARGETS = gsend grec

# Default target: build all programs
all: $(TARGETS)

# Build gsend executable
# Links with OpenSSL libraries for encryption operations
gsend: gsend.cpp
	$(CXX) $(CXXFLAGS) -o gsend gsend.cpp $(LDFLAGS)

# Build grec executable
# Links with OpenSSL libraries for decryption operations
grec: grec.cpp
	$(CXX) $(CXXFLAGS) -o grec grec.cpp $(LDFLAGS)

# Clean target: remove all built executables
clean:
	rm -f $(TARGETS)
	rm -f *.o
	rm -f *.FIU

# Phony targets (not actual files)
.PHONY: all clean
