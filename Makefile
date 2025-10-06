# ============================================================================
# Makefile for gsend and grec - File Encryption/Decryption Utilities
# ============================================================================
#
# PURPOSE:
# This Makefile automates the compilation of the file encryption suite
# consisting of two programs: gsend (encryption/sender) and grec (decryption/
# receiver). Both programs rely on the OpenSSL library for cryptographic
# operations.
#
# PROGRAMS BUILT:
# 1. gsend - Encrypts files using AES-256-CBC and HMAC-SHA512
# 2. grec  - Decrypts files and verifies HMAC authentication
#
# USAGE:
#   make        - Build both programs (default target)
#   make all    - Same as 'make' (builds both programs)
#   make clean  - Remove compiled binaries, object files, and test files
#   make gsend  - Build only the gsend program
#   make grec   - Build only the grec program
#
# REQUIREMENTS:
# - g++ compiler with C++11 support
# - OpenSSL development libraries (libssl-dev on Ubuntu/Debian)
# - POSIX-compliant system (Linux, macOS, *BSD, etc.)
#
# CROSS-PLATFORM COMPATIBILITY:
# This Makefile automatically detects the operating system:
# - On macOS (Darwin): Adds Homebrew OpenSSL paths if needed
# - On Linux: Uses system OpenSSL libraries
# - This ensures the same Makefile works on different platforms
#
# AUTHOR: Andres Mendez
# COURSE: Applied Cryptography
# ASSIGNMENT: 2 (File Encryption Suite)
# ============================================================================

# ============================================================================
# COMPILER AND FLAGS
# ============================================================================

# Compiler Selection
# CXX = g++
# - Uses the GNU C++ compiler (g++)
# - On most systems, this is symlinked to the default C++ compiler
# - Alternative: clang++ (LLVM compiler, common on macOS)
CXX = g++

# Compiler Flags
# CXXFLAGS controls compiler behavior and optimizations
# Breakdown of flags:
#   -std=c++11    : Use C++11 standard (required for range-based for loops,
#                   auto keyword, etc.)
#   -Wall         : Enable all common warnings (helps catch potential bugs)
#   -Wextra       : Enable extra warnings beyond -Wall
#   -O2           : Optimization level 2 (balances speed and compile time)
#                   O0 = no optimization (fast compile, slow execution)
#                   O2 = good optimization (recommended for release)
#                   O3 = aggressive optimization (may increase binary size)
CXXFLAGS = -std=c++11 -Wall -Wextra -O2

# Linker Flags
# LDFLAGS controls linking behavior and specifies libraries to link against
# Breakdown:
#   -lssl         : Link against OpenSSL library (libssl.so or libssl.dylib)
#   -lcrypto      : Link against OpenSSL crypto library (libcrypto)
#                   These libraries provide AES, HMAC, PBKDF2, etc.
LDFLAGS = -lssl -lcrypto

# ============================================================================
# PLATFORM DETECTION AND CONDITIONAL CONFIGURATION
# ============================================================================

# Detect Operating System
# The 'uname -s' command returns the OS name:
#   - Darwin  = macOS
#   - Linux   = Linux
#   - FreeBSD = FreeBSD
#   - etc.
# $(shell ...) executes the command and captures its output
UNAME_S := $(shell uname -s)

# macOS-Specific Configuration
# On macOS, Homebrew installs OpenSSL in a non-standard location
# We need to add include and library paths for the compiler to find it
ifeq ($(UNAME_S),Darwin)
    # Add Homebrew OpenSSL include directory to search path
    # This allows #include <openssl/...> to work
    CXXFLAGS += -I/opt/homebrew/opt/openssl@3/include

    # Add Homebrew OpenSSL library directory to linker search path
    # The := assignment re-evaluates LDFLAGS with library path prepended
    # This ensures -L flag comes before -l flags
    LDFLAGS := -L/opt/homebrew/opt/openssl@3/lib $(LDFLAGS)
endif

# Linux Configuration (Implicit)
# On Linux, OpenSSL is typically installed in standard system locations:
#   /usr/include/openssl  (headers)
#   /usr/lib             (libraries)
# No special flags needed - the compiler finds them automatically

# ============================================================================
# TARGET DEFINITIONS
# ============================================================================

# Target Executables
# TARGETS lists all programs to be built
# This variable is used by the 'all' and 'clean' targets
TARGETS = gsend grec

# ============================================================================
# BUILD RULES
# ============================================================================

# Default Target: all
# When you run 'make' without arguments, it executes the first target
# The 'all' target depends on $(TARGETS), which expands to 'gsend grec'
# This causes Make to build both programs
all: $(TARGETS)

# Rule to Build gsend
# Target:       gsend (the executable we want to create)
# Dependency:   gsend.cpp (the source file)
# Recipe:       Compile gsend.cpp and link with OpenSSL libraries
#
# How it works:
# 1. Make checks if gsend.cpp is newer than gsend (or if gsend doesn't exist)
# 2. If rebuild is needed, execute the recipe (command)
# 3. $(CXX) expands to 'g++'
# 4. $(CXXFLAGS) expands to compiler flags
# 5. -o gsend specifies the output filename
# 6. gsend.cpp is the input source file
# 7. $(LDFLAGS) expands to linker flags (-lssl -lcrypto)
gsend: gsend.cpp
	$(CXX) $(CXXFLAGS) -o gsend gsend.cpp $(LDFLAGS)

# Rule to Build grec
# Target:       grec (the executable we want to create)
# Dependency:   grec.cpp (the source file)
# Recipe:       Compile grec.cpp and link with OpenSSL libraries
#
# Same principle as gsend rule above
grec: grec.cpp
	$(CXX) $(CXXFLAGS) -o grec grec.cpp $(LDFLAGS)

# ============================================================================
# CLEANUP RULES
# ============================================================================

# Clean Target
# Removes all generated files to provide a fresh start
# Usage: make clean
#
# This target has no dependencies, so it always runs when requested
# The rm command removes files:
#   -f flag: force removal (don't prompt, don't error if file doesn't exist)
#
# Files removed:
#   $(TARGETS)  - Expands to 'gsend grec' (the executables)
#   *.o        - All object files (*.o) if any were created
#   *.FIU      - All encrypted test files
#
# Note: The @ prefix suppresses echoing of commands (optional)
clean:
	rm -f $(TARGETS)
	rm -f *.o
	rm -f *.FIU

# ============================================================================
# PHONY TARGETS
# ============================================================================

# Phony Targets Declaration
# .PHONY tells Make that these targets don't represent actual files
# This prevents conflicts if files named 'all' or 'clean' exist
#
# Why this matters:
# - Without .PHONY, if a file named 'clean' exists, 'make clean' would
#   do nothing (Make would think the target is up-to-date)
# - .PHONY forces Make to always run these targets
.PHONY: all clean

# ============================================================================
# USAGE EXAMPLES
# ============================================================================
#
# Basic Compilation:
#   $ make
#   This builds both gsend and grec
#
# Rebuild After Changes:
#   $ make clean
#   $ make
#   This ensures a clean rebuild
#
# Build Only One Program:
#   $ make gsend
#   This builds only gsend, not grec
#
# Parallel Build (faster on multi-core systems):
#   $ make -j4
#   This uses 4 parallel jobs to compile
#
# Verbose Mode (see full commands):
#   $ make VERBOSE=1
#   Shows the full compilation commands
#
# Override Compiler:
#   $ make CXX=clang++
#   Uses clang++ instead of g++
#
# Override Flags:
#   $ make CXXFLAGS="-std=c++11 -O3 -march=native"
#   Uses aggressive optimization
#
# ============================================================================
# DEBUGGING THE MAKEFILE
# ============================================================================
#
# To see what Make is doing:
#   $ make -n
#   Shows commands without executing them (dry run)
#
# To see variable values:
#   $ make -p
#   Prints the database (shows all variables and rules)
#
# To debug a specific variable:
#   Add to this Makefile:
#   $(info CXXFLAGS is $(CXXFLAGS))
#   $(info LDFLAGS is $(LDFLAGS))
#
# ============================================================================
