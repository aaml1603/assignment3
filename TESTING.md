# Testing Instructions for gsend/grec

This document provides comprehensive testing instructions for the file encryption/decryption suite.

## Prerequisites

Ensure the programs are compiled:
```bash
cd ~/mendez-assign2
make clean && make
```

---

## Test 1: Basic Encryption/Decryption (Local Mode)

This test verifies basic encryption and decryption functionality.

```bash
# 1. Create a test file
echo "This is my test file!" > mytest.txt

# 2. Encrypt it
./gsend mytest.txt -l
# Enter password when prompted (e.g., "hello")

# Expected output:
# - Password prompt
# - Key printed in hexadecimal format
# - "Successfully encrypted mytest.txt to mytest.txt.FIU (XXX bytes written)"

# 3. Remove the original file
rm mytest.txt

# 4. Decrypt the encrypted file
./grec mytest.txt -l
# Enter the same password used for encryption

# Expected output:
# - Password prompt
# - Same key in hexadecimal format
# - "Successfully received and decrypted mytest.txt (XXX bytes written)"

# 5. Verify the decrypted content
cat mytest.txt
# Should display: "This is my test file!"
```

**Expected Result:** ✅ File encrypts and decrypts successfully, content is identical.

---

## Test 2: Assignment's Exact Test Sequence

This follows the exact test sequence from the assignment description.

```bash
# 1. Copy gsend executable to testfile.check
cp gsend testfile.check

# 2. Encrypt testfile.check
./gsend testfile.check -l
# Enter password: test123

# 3. Remove original
rm testfile.check

# 4. Decrypt it
./grec testfile.check.FIU -l
# Enter password: test123

# 5. Compare decrypted file with original gsend binary
diff testfile.check gsend
```

**Expected Result:** ✅ No output from diff means files are identical.

---

## Test 3: HMAC Tampering Detection

This test verifies that HMAC authentication detects file tampering.

```bash
# 1. Create and encrypt a file
echo "secret data" > secret.txt
./gsend secret.txt -l
# Password: mypass

# 2. Tamper with the encrypted file
echo "CORRUPTED" >> secret.txt.FIU

# 3. Remove original and try to decrypt
rm secret.txt
./grec secret.txt -l
# Password: mypass

# 4. Check exit code
echo "Exit code: $?"
```

**Expected Result:** 
- ✅ Error message: "Error: HMAC verification failed"
- ✅ Exit code: 62

---

## Test 4: Wrong Password Detection

This test verifies that using an incorrect password is detected.

```bash
# 1. Create and encrypt a file
echo "secure data" > secure.txt
./gsend secure.txt -l
# Password: correctpass

# 2. Try to decrypt with wrong password
rm secure.txt
./grec secure.txt -l
# Password: wrongpass

# 3. Check exit code
echo "Exit code: $?"
```

**Expected Result:**
- ✅ Error message: "Error: HMAC verification failed"
- ✅ Exit code: 62

---

## Test 5: File Already Exists Error

This test verifies proper error handling when output file exists.

```bash
# 1. Create and encrypt a file
echo "data" > test.txt
./gsend test.txt -l
# Password: pass

# 2. Try to encrypt again without removing .FIU file
./gsend test.txt -l
# Password: pass

# 3. Check exit code
echo "Exit code: $?"
```

**Expected Result:**
- ✅ Error message: "Error: Output file already exists"
- ✅ Exit code: 33

---

## Test 6: Network Transmission (Requires Two Terminals)

This test verifies network file transmission functionality.

### Terminal 1 (Receiver):
```bash
cd ~/mendez-assign2

# Start grec in daemon mode on port 9999
./grec received_file -d 9999
# Password: netpass
# Should display: "Waiting for connections."
```

### Terminal 2 (Sender):
```bash
cd ~/mendez-assign2

# Create a test file
echo "Network transmission test!" > network.txt

# Encrypt and send over network
./gsend network.txt -d 127.0.0.1:9999
# Password: netpass

# Expected output:
# - "Transmitting to 127.0.0.1:9999"
# - "Successfully received"
```

### Back to Terminal 1:
```bash
# Verify the received and decrypted file
cat received_file
# Should display: "Network transmission test!"
```

**Expected Result:** ✅ File transmitted, received, and decrypted successfully over network.

---

## Test 7: PBKDF2 Key Derivation Verification

This test verifies the key derivation function with a known password.

```bash
# Test with password "hello"
echo "test" > test.txt
echo "hello" | ./gsend test.txt -l

# Note the Key output (hexadecimal format)
# Should be consistent across runs with same password
```

**Expected Result:** ✅ Key is derived using PBKDF2 with SHA-512, 4096 iterations, and salt "KCl".

---

## Test 8: Binary File Encryption

This test verifies that binary files (not just text) can be encrypted.

```bash
# Use the compiled binary as test input
cp gsend binary_test
./gsend binary_test -l
# Password: binarytest

rm binary_test
./grec binary_test -l
# Password: binarytest

# Compare
diff binary_test gsend
```

**Expected Result:** ✅ Binary files encrypt and decrypt without corruption.

---

## Quick Sanity Check

Run all essential tests in sequence:

```bash
cd ~/mendez-assign2

# Clean and rebuild
make clean && make

# Run the assignment's exact test
cp gsend testfile.check
./gsend testfile.check -l
rm testfile.check
./grec testfile.check.FIU -l
diff testfile.check gsend

# If diff produces no output: ALL TESTS PASSED ✅
```

---

## Summary of Expected Behaviors

| Feature | Expected Behavior |
|---------|-------------------|
| Local encryption | Creates .FIU file with encrypted content + HMAC |
| Local decryption | Removes .FIU extension, verifies HMAC, decrypts |
| Network mode | Transmits encrypted file over TCP/IP |
| HMAC verification | Detects tampering or wrong password |
| Exit code 33 | Output file already exists |
| Exit code 62 | HMAC verification failed |
| Key derivation | PBKDF2, SHA-512, 4096 iterations, salt "KCl" |
| Encryption | AES-256-CBC with random IV |
| IV handling | Prepended to encrypted data |
| HMAC | SHA-512, appended after encrypted data |

---

## Troubleshooting

**Problem:** Connection refused in network mode  
**Solution:** Ensure receiver (grec -d) is started before sender (gsend -d)

**Problem:** HMAC verification always fails  
**Solution:** Verify you're using the exact same password for encryption and decryption

**Problem:** File not found  
**Solution:** Check that .FIU extension is handled correctly by both programs

**Problem:** Compilation errors  
**Solution:** Ensure OpenSSL development libraries are installed

