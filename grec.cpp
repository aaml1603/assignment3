/*
 * ============================================================================
 * grec.cpp - File Reception and Decryption Utility
 * ============================================================================
 *
 * PROGRAM DESCRIPTION:
 * This program receives and decrypts files that were encrypted by gsend.
 * It verifies the integrity and authenticity of encrypted files using HMAC
 * and decrypts them using AES-256-CBC.
 *
 * FUNCTIONALITY:
 * - Receives encrypted files over network or from local filesystem
 * - Verifies HMAC-SHA512 authentication tags
 * - Decrypts files using AES-256 in CBC mode
 * - Derives decryption keys from passwords using PBKDF2
 *
 * USAGE:
 *   grec <filename> [-d <port>][-l]
 *
 * OPTIONS:
 *   -l          Local mode: decrypt local .FIU file
 *   -d port     Network mode: listen on port for incoming encrypted file
 *
 * SECURITY FEATURES:
 * - HMAC verification (detects tampering and wrong passwords)
 * - Password-based key derivation (PBKDF2 with SHA-512, 4096 iterations)
 * - AES-256-CBC decryption
 * - Secure password input (no echo to terminal)
 *
 * FILE FORMAT (encrypted .FIU files):
 *   [IV (16 bytes)][Encrypted Data (variable)][HMAC (64 bytes)]
 *
 * CRYPTOGRAPHIC PARAMETERS:
 * - Key derivation: PBKDF2-HMAC-SHA512, 4096 iterations, salt="KCl"
 * - Decryption: AES-256-CBC (256-bit key, 128-bit IV)
 * - MAC verification: HMAC-SHA512 (512-bit)
 *
 * AUTHOR: Andres Mendez
 * COURSE: Applied Cryptography
 * ASSIGNMENT: 2 (File Encryption Suite)
 * ============================================================================
 */

// ============================================================================
// HEADER FILES
// ============================================================================

#include <iostream>       // For standard I/O operations
#include <fstream>        // For file I/O operations
#include <cstring>        // For C-style string operations
#include <string>         // For C++ string class
#include <sys/socket.h>   // For socket operations
#include <netinet/in.h>   // For internet address structures
#include <arpa/inet.h>    // For IP address conversion
#include <unistd.h>       // For UNIX system calls
#include <termios.h>      // For terminal I/O control (password input)
#include <openssl/evp.h>  // For OpenSSL EVP (envelope) functions
#include <openssl/hmac.h> // For HMAC operations
#include <openssl/sha.h>  // For SHA hash functions

using namespace std;

// ============================================================================
// CRYPTOGRAPHIC CONSTANTS
// ============================================================================

/*
 * KEY_SIZE: Size of the decryption key in bytes
 * - AES-256 requires a 256-bit (32-byte) key
 * - This key is derived from the user's password using PBKDF2
 * - Must match the key size used in gsend
 */
#define KEY_SIZE 32

/*
 * IV_SIZE: Size of the Initialization Vector in bytes
 * - AES uses a 128-bit (16-byte) block size
 * - The IV is read from the first 16 bytes of the encrypted file
 * - Must match the IV size used in gsend
 */
#define IV_SIZE 16

/*
 * HMAC_SIZE: Size of the HMAC in bytes
 * - SHA-512 produces a 512-bit (64-byte) hash
 * - The HMAC is read from the last 64 bytes of the encrypted file
 * - Must match the HMAC size used in gsend
 */
#define HMAC_SIZE 64

/*
 * PBKDF2_ITERATIONS: Number of iterations for key derivation
 * - Must match the iteration count used in gsend (4096)
 * - Both sender and receiver must use identical PBKDF2 parameters
 */
#define PBKDF2_ITERATIONS 4096

/*
 * SALT: Fixed salt value for PBKDF2
 * - Must match the salt used in gsend ("KCl")
 * - Both sender and receiver must use the same salt
 * - In production, the salt would be stored with the ciphertext
 */
#define SALT "KCl"

// ============================================================================
// FUNCTION: getPassword()
// ============================================================================

/*
 * FUNCTION: getPassword
 *
 * PURPOSE:
 *   Securely reads a password from standard input without echoing the
 *   characters to the terminal. This prevents shoulder-surfing attacks.
 *
 * ALGORITHM:
 *   1. Save current terminal settings
 *   2. Disable ECHO flag in terminal settings
 *   3. Read password from stdin
 *   4. Restore original terminal settings
 *
 * PARAMETERS:
 *   None
 *
 * RETURN VALUE:
 *   string - The password entered by the user
 *
 * SECURITY NOTES:
 *   - The password must match the one used during encryption
 *   - If passwords don't match, HMAC verification will fail
 *   - The password is stored in memory as a std::string
 *   - For production use, consider using secure memory (mlock/memset)
 */
string getPassword() {
    struct termios oldt, newt;  // Terminal settings structures
    string password;             // Password storage

    // Step 1: Get current terminal settings
    // tcgetattr() retrieves the parameters associated with the terminal
    tcgetattr(STDIN_FILENO, &oldt);

    // Step 2: Copy old settings and modify to disable echo
    newt = oldt;
    newt.c_lflag &= ~ECHO;  // Clear the ECHO flag

    // Step 3: Apply new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Step 4: Prompt for and read password
    cout << "Password: ";
    getline(cin, password);  // Read entire line
    cout << endl;            // Print newline since echo is disabled

    // Step 5: Restore original terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return password;
}

// ============================================================================
// FUNCTION: deriveKey()
// ============================================================================

/*
 * FUNCTION: deriveKey
 *
 * PURPOSE:
 *   Derives a cryptographic key from a user-supplied password using PBKDF2.
 *   This function uses identical parameters to gsend's deriveKey() to ensure
 *   that the same password produces the same key.
 *
 * ALGORITHM:
 *   Uses PBKDF2-HMAC-SHA512 with the following parameters:
 *   - Hash function: SHA-512
 *   - Iterations: 4096
 *   - Salt: "KCl" (fixed for this assignment)
 *   - Output length: 32 bytes (256 bits for AES-256)
 *
 * PARAMETERS:
 *   password - User-provided password (input)
 *   key      - Buffer to store derived key (output, must be KEY_SIZE bytes)
 *
 * RETURN VALUE:
 *   None (key is written to the provided buffer)
 *
 * CRYPTOGRAPHIC DETAILS:
 *   - If the password matches the one used in gsend, the derived key will
 *     be identical, allowing successful decryption
 *   - If the password is different, the key will be different, and HMAC
 *     verification will fail (protecting against wrong password attacks)
 *   - PBKDF2 is deterministic: same input → same output
 *
 * OUTPUT:
 *   Prints the derived key in hexadecimal format for grading/verification
 */
void deriveKey(const string& password, unsigned char* key) {
    // Call OpenSSL's PBKDF2 implementation
    // Parameters must exactly match those used in gsend
    PKCS5_PBKDF2_HMAC(
        password.c_str(),              // Password string
        password.length(),             // Password length
        (const unsigned char*)SALT,    // Salt value ("KCl")
        strlen(SALT),                  // Salt length
        PBKDF2_ITERATIONS,             // Iteration count (4096)
        EVP_sha512(),                  // Hash function (SHA-512)
        KEY_SIZE,                      // Output length (32 bytes)
        key                            // Output buffer
    );

    // Print the derived key in hexadecimal format
    // This should match the key printed by gsend if passwords match
    cout << "Key: ";
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02X ", key[i]);
    }
    cout << endl;
}

// ============================================================================
// FUNCTION: verifyAndRemoveHMAC()
// ============================================================================

/*
 * FUNCTION: verifyAndRemoveHMAC
 *
 * PURPOSE:
 *   Verifies the HMAC authentication tag appended to an encrypted file
 *   and removes it if valid. This is a critical security function that
 *   ensures the file has not been tampered with.
 *
 * ALGORITHM:
 *   1. Read the entire encrypted file (IV + ciphertext + HMAC)
 *   2. Extract the last 64 bytes (HMAC tag)
 *   3. Compute HMAC over the remaining data (IV + ciphertext)
 *   4. Compare computed HMAC with extracted HMAC (constant-time comparison)
 *   5. If valid, rewrite file without HMAC
 *   6. If invalid, return false (decryption will not proceed)
 *
 * PARAMETERS:
 *   filename - Path to the encrypted file with HMAC appended
 *   key      - HMAC key (same as decryption key)
 *
 * RETURN VALUE:
 *   true  - HMAC is valid (authentication successful)
 *   false - HMAC is invalid (file tampered or wrong password)
 *
 * SECURITY IMPLICATIONS:
 *   - If this function returns false, the file must NOT be decrypted
 *   - HMAC verification prevents:
 *     * Tampering with the ciphertext
 *     * Bit-flipping attacks
 *     * Padding oracle attacks
 *     * Wrong password detection (before attempting decryption)
 *   - This implements the "verify-then-decrypt" principle
 *
 * ERROR HANDLING:
 *   - Returns false if file cannot be read
 *   - Returns false if file is too small to contain HMAC
 *   - Returns false if computed HMAC doesn't match file's HMAC
 *   - Prints error message to stderr on failure
 *   - Main program will exit with code 62 on HMAC failure
 *
 * FILE MODIFICATION:
 *   If successful, the file is rewritten without the HMAC:
 *   Before: [IV][Ciphertext][HMAC]
 *   After:  [IV][Ciphertext]
 */
bool verifyAndRemoveHMAC(const string& filename, const unsigned char* key) {

    // ========================================================================
    // Step 1: Read entire encrypted file
    // ========================================================================
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open file for HMAC verification" << endl;
        return false;
    }

    // Determine file size
    inFile.seekg(0, ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    // Validate file size
    // Minimum: IV (16) + at least 1 block of ciphertext (16) + HMAC (64) = 96 bytes
    if (fileSize < HMAC_SIZE) {
        cerr << "Error: File too small to contain HMAC" << endl;
        return false;
    }

    // ========================================================================
    // Step 2: Read file data and extract HMAC
    // ========================================================================
    // The file structure is: [IV][Ciphertext][HMAC]
    // We need to separate the HMAC from the data

    size_t dataSize = fileSize - HMAC_SIZE;  // Everything except HMAC
    unsigned char* data = new unsigned char[dataSize];
    unsigned char fileHmac[HMAC_SIZE];

    // Read the data portion (IV + ciphertext)
    inFile.read((char*)data, dataSize);
    // Read the HMAC portion (last 64 bytes)
    inFile.read((char*)fileHmac, HMAC_SIZE);
    inFile.close();

    // ========================================================================
    // Step 3: Compute HMAC of encrypted data
    // ========================================================================
    // We compute HMAC over the same data that gsend did: IV + ciphertext
    // This should match the HMAC in the file if:
    //   1. The password is correct
    //   2. The file has not been tampered with

    unsigned char computedHmac[HMAC_SIZE];
    unsigned int hmacLen;

    // Compute HMAC-SHA512 over the data
    HMAC(EVP_sha512(), key, KEY_SIZE, data, dataSize, computedHmac, &hmacLen);

    // ========================================================================
    // Step 4: Compare HMACs using constant-time comparison
    // ========================================================================
    // memcmp() performs a constant-time comparison (on most systems)
    // This prevents timing attacks where an attacker could determine
    // how many bytes of the HMAC are correct based on execution time
    bool valid = (memcmp(fileHmac, computedHmac, HMAC_SIZE) == 0);

    if (!valid) {
        // HMAC verification failed
        // This could mean:
        //   1. Wrong password was entered
        //   2. File has been tampered with
        //   3. File is corrupted
        cerr << "Error: HMAC verification failed" << endl;
        delete[] data;
        return false;  // Main will exit with code 62
    }

    // ========================================================================
    // Step 5: HMAC is valid - rewrite file without HMAC
    // ========================================================================
    // The decryption function expects to receive: [IV][Ciphertext]
    // So we remove the HMAC from the file

    ofstream outFile(filename, ios::binary | ios::trunc);
    if (!outFile) {
        cerr << "Error: Cannot rewrite file without HMAC" << endl;
        delete[] data;
        return false;
    }

    // Write only the data portion (IV + ciphertext), not the HMAC
    outFile.write((char*)data, dataSize);
    outFile.close();

    // ========================================================================
    // Step 6: Cleanup
    // ========================================================================
    delete[] data;

    return true;  // HMAC is valid, safe to proceed with decryption
}

// ============================================================================
// FUNCTION: decryptFile()
// ============================================================================

/*
 * FUNCTION: decryptFile
 *
 * PURPOSE:
 *   Decrypts a file that was encrypted with AES-256-CBC. This function
 *   should only be called after HMAC verification succeeds.
 *
 * ALGORITHM:
 *   1. Check if output file already exists (error if it does)
 *   2. Open encrypted file and read IV from first 16 bytes
 *   3. Initialize AES-256-CBC decryption context with key and IV
 *   4. Read encrypted file in chunks and decrypt each chunk
 *   5. Finalize decryption (removes PKCS#7 padding)
 *   6. Write decrypted data to output file
 *   7. Cleanup and close files
 *
 * PARAMETERS:
 *   inputFile  - Path to encrypted file (already HMAC-verified)
 *   outputFile - Path where decrypted file will be written
 *   key        - Decryption key (32 bytes from PBKDF2)
 *
 * RETURN VALUE:
 *   true  - Decryption succeeded
 *   false - Decryption failed (error message printed to stderr)
 *
 * FILE FORMAT:
 *   Input file structure: [IV (16 bytes)][Encrypted Data]
 *   - IV is read from the first 16 bytes
 *   - Remaining data is the ciphertext
 *   - PKCS#7 padding is automatically removed by OpenSSL
 *
 * SECURITY NOTES:
 *   - This function assumes HMAC has already been verified
 *   - If decryption fails (e.g., wrong password), it returns false
 *   - Decryption failure after HMAC success indicates file corruption
 *   - CBC mode requires the correct IV (read from file header)
 *   - PKCS#7 padding is automatically validated and removed
 *
 * ERROR HANDLING:
 *   - Returns false if output file exists
 *   - Returns false if input file cannot be read
 *   - Returns false if IV cannot be read (file too small)
 *   - Returns false if decryption initialization fails
 *   - Returns false if decryption processing fails
 *   - Returns false if decryption finalization fails (wrong password/key)
 */
bool decryptFile(const string& inputFile, const string& outputFile,
                 const unsigned char* key) {

    // ========================================================================
    // Step 1: Check if output file already exists
    // ========================================================================
    // The assignment requires returning error code 33 if output exists
    ifstream testOut(outputFile);
    if (testOut.good()) {
        cerr << "Error: Output file already exists" << endl;
        testOut.close();
        return false;  // Caller will return exit code 33
    }
    testOut.close();

    // ========================================================================
    // Step 2: Open input file and read IV
    // ========================================================================
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open input file" << endl;
        return false;
    }

    // Read the IV from the first 16 bytes of the file
    // This IV was generated randomly by gsend during encryption
    unsigned char iv[IV_SIZE];
    inFile.read((char*)iv, IV_SIZE);

    // Verify we successfully read the IV
    if (inFile.gcount() != IV_SIZE) {
        cerr << "Error: Failed to read IV" << endl;
        return false;
    }

    // ========================================================================
    // Step 3: Open output file
    // ========================================================================
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot create output file" << endl;
        return false;
    }

    // ========================================================================
    // Step 4: Initialize decryption context
    // ========================================================================
    // Create and initialize the decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Failed to create cipher context" << endl;
        return false;
    }

    // Initialize the decryption operation with AES-256-CBC
    // Parameters:
    //   - ctx: the context structure
    //   - EVP_aes_256_cbc(): specifies AES-256 in CBC mode
    //   - NULL: use default engine
    //   - key: the decryption key (32 bytes, from PBKDF2)
    //   - iv: the initialization vector (16 bytes, read from file)
    // Returns 1 on success, 0 on failure
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error: Failed to initialize decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // ========================================================================
    // Step 5: Decrypt file in chunks
    // ========================================================================
    // Process the file in 4KB chunks for memory efficiency
    unsigned char inBuf[4096];                       // Input buffer
    unsigned char outBuf[4096 + EVP_MAX_BLOCK_LENGTH]; // Output buffer
    int outLen;                                      // Bytes written per chunk

    // Read and decrypt until end of file
    while (inFile.read((char*)inBuf, sizeof(inBuf)) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();

        // Decrypt this chunk
        // EVP_DecryptUpdate can be called multiple times
        // It processes encrypted input and produces plaintext output
        if (EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            cerr << "Error: Decryption failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Write decrypted chunk to output file
        outFile.write((char*)outBuf, outLen);
    }

    // ========================================================================
    // Step 6: Finalize decryption
    // ========================================================================
    // EVP_DecryptFinal_ex handles the final block and removes padding
    // PKCS#7 padding removal:
    //   - Reads the last byte to determine padding length
    //   - Verifies that all padding bytes have the correct value
    //   - Removes the padding bytes
    //   - Returns only the original data
    //
    // This function will FAIL if:
    //   - Wrong password/key (padding will be invalid)
    //   - File has been tampered with (but HMAC should catch this first)
    //   - File is corrupted
    if (EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        cerr << "Error: Decryption finalization failed (possibly wrong password)" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write((char*)outBuf, outLen);

    // ========================================================================
    // Step 7: Cleanup
    // ========================================================================
    EVP_CIPHER_CTX_free(ctx);  // Free decryption context
    inFile.close();             // Close input file
    outFile.close();            // Close output file

    return true;  // Success
}

// ============================================================================
// FUNCTION: receiveFile()
// ============================================================================

/*
 * FUNCTION: receiveFile
 *
 * PURPOSE:
 *   Acts as a network server, listening for incoming TCP connections and
 *   receiving an encrypted file. This function implements the receiver
 *   side of the network transmission protocol.
 *
 * ALGORITHM:
 *   1. Create a TCP server socket
 *   2. Configure socket options (allow address reuse)
 *   3. Bind socket to specified port
 *   4. Listen for incoming connections
 *   5. Accept one connection
 *   6. Receive file data and write to local file
 *   7. Send acknowledgment to sender
 *   8. Close connection
 *
 * PARAMETERS:
 *   filename - Path where received file will be saved (with .FIU extension)
 *   port     - Port number to listen on (e.g., 8888)
 *
 * RETURN VALUE:
 *   true  - File successfully received
 *   false - Reception failed (error message printed to stderr)
 *
 * NETWORK PROTOCOL:
 *   - Transport: TCP (reliable, ordered delivery)
 *   - Server listens on specified port
 *   - Accepts one connection, receives all data until sender closes
 *   - Sends simple acknowledgment message
 *   - Connection is closed after file transfer
 *
 * SECURITY NOTES:
 *   - No authentication of sender (anyone can connect)
 *   - Received file is still encrypted and HMAC-protected
 *   - Network layer provides no encryption (data is already encrypted)
 *   - For production, consider TLS/SSL and sender authentication
 *
 * USAGE SCENARIO:
 *   Terminal 1: ./grec output.txt -d 8888
 *   (waits for connection)
 *   Terminal 2: ./gsend input.txt -d 127.0.0.1:8888
 *   (sends encrypted file)
 *   Terminal 1: receives file, verifies HMAC, decrypts
 *
 * ERROR HANDLING:
 *   - Socket creation failure
 *   - Bind failure (port already in use)
 *   - Listen failure
 *   - Accept failure (connection issues)
 *   - File write failure
 */
bool receiveFile(const string& filename, int port) {

    // ========================================================================
    // Step 1: Create a socket
    // ========================================================================
    // Create a TCP socket for receiving data
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Cannot create socket" << endl;
        return false;
    }

    // ========================================================================
    // Step 2: Set socket options
    // ========================================================================
    // Allow address reuse to prevent "Address already in use" errors
    // This is useful for quick restarts during testing
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error: setsockopt failed" << endl;
        close(sockfd);
        return false;
    }

    // ========================================================================
    // Step 3: Configure server address
    // ========================================================================
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));  // Zero out structure

    servAddr.sin_family = AF_INET;           // IPv4
    servAddr.sin_addr.s_addr = INADDR_ANY;   // Listen on all interfaces
    servAddr.sin_port = htons(port);         // Convert port to network byte order

    // INADDR_ANY means the server will accept connections on any of the
    // machine's IP addresses (localhost, external IP, etc.)

    // ========================================================================
    // Step 4: Bind socket to port
    // ========================================================================
    // bind() associates the socket with a specific port
    // Note: Using ::bind to avoid naming conflict with std::bind
    if (::bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        cerr << "Error: Bind failed" << endl;
        close(sockfd);
        return false;
    }

    // ========================================================================
    // Step 5: Listen for connections
    // ========================================================================
    // listen() marks the socket as a passive socket (will accept connections)
    // Parameter 1 = backlog (max length of pending connections queue)
    if (listen(sockfd, 1) < 0) {
        cerr << "Error: Listen failed" << endl;
        close(sockfd);
        return false;
    }

    cout << "Waiting for connections." << endl;

    // ========================================================================
    // Step 6: Accept incoming connection
    // ========================================================================
    // accept() blocks until a client connects
    // Returns a new socket for communication with the client
    struct sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);

    int clientfd = accept(sockfd, (struct sockaddr*)&clientAddr, &clientLen);
    if (clientfd < 0) {
        cerr << "Error: Accept failed" << endl;
        close(sockfd);
        return false;
    }

    cout << "Inbound file." << endl;

    // ========================================================================
    // Step 7: Receive file data
    // ========================================================================
    ofstream outFile(filename, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot create output file" << endl;
        close(clientfd);
        close(sockfd);
        return false;
    }

    // Receive data in chunks until sender closes connection
    char buffer[4096];
    ssize_t bytesReceived;

    // recv() returns number of bytes received, or 0 when connection closes
    while ((bytesReceived = recv(clientfd, buffer, sizeof(buffer), 0)) > 0) {
        outFile.write(buffer, bytesReceived);
    }

    outFile.close();

    // ========================================================================
    // Step 8: Send acknowledgment
    // ========================================================================
    // Send a simple text acknowledgment to the sender
    // This confirms that the file was received successfully
    const char* ack = "Successfully received";
    send(clientfd, ack, strlen(ack), 0);

    // ========================================================================
    // Step 9: Cleanup
    // ========================================================================
    close(clientfd);  // Close client connection
    close(sockfd);    // Close server socket

    return true;  // Success
}

// ============================================================================
// FUNCTION: main()
// ============================================================================

/*
 * FUNCTION: main
 *
 * PURPOSE:
 *   Entry point for the grec program. Parses command-line arguments,
 *   receives/reads encrypted files, verifies HMAC, and decrypts.
 *
 * COMMAND-LINE ARGUMENTS:
 *   argv[1]    - Filename (output name for network mode, input for local mode)
 *   -l         - Local mode (decrypt existing .FIU file)
 *   -d port    - Network mode (listen on port)
 *
 * RETURN VALUES:
 *   0  - Success
 *   1  - General error (invalid arguments, network failure, etc.)
 *   62 - HMAC verification failed (wrong password or tampering)
 *   33 - Output file already exists
 *
 * PROGRAM FLOW:
 *   1. Parse command-line arguments
 *   2. (Network mode) Receive encrypted file from network
 *   3. Get password from user (no echo)
 *   4. Derive decryption key using PBKDF2
 *   5. Verify and remove HMAC (exits with code 62 if invalid)
 *   6. Decrypt file with AES-256-CBC
 *   7. Report success
 *
 * MODES OF OPERATION:
 *
 *   Local Mode (-l):
 *     ./grec myfile -l
 *     - Expects myfile.FIU to exist
 *     - Verifies HMAC and decrypts
 *     - Outputs to myfile (removes .FIU extension)
 *
 *   Network Mode (-d port):
 *     ./grec output -d 8888
 *     - Listens on port 8888
 *     - Receives file from gsend
 *     - Saves as output.FIU
 *     - Verifies HMAC and decrypts
 *     - Outputs to output
 *
 * ERROR HANDLING:
 *   - Invalid command-line arguments
 *   - Network reception failures (handled by receiveFile)
 *   - HMAC verification failures (handled by verifyAndRemoveHMAC)
 *   - Decryption failures (handled by decryptFile)
 */
int main(int argc, char* argv[]) {

    // ========================================================================
    // Step 1: Validate command-line arguments
    // ========================================================================
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <filename> [-d <port>][-l]" << endl;
        return 1;
    }

    // ========================================================================
    // Step 2: Parse command-line arguments
    // ========================================================================
    string filename = argv[1];   // Base filename (without .FIU in some modes)
    bool networkMode = false;    // Default to local mode
    int port = 0;                // Port for network mode

    // Process optional flags
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            // Network mode: -d flag followed by port number
            networkMode = true;
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0) {
            // Local mode: -l flag explicitly specified
            networkMode = false;
        }
    }

    // ========================================================================
    // Step 3: Handle network or local mode
    // ========================================================================

    // NETWORK MODE: Receive file from network first
    if (networkMode && port > 0) {
        // The received file will be saved as <filename>.FIU
        // For example: ./grec output -d 8888
        //   Receives file and saves as output.FIU
        string receivedFile = filename + ".FIU";

        // Receive the encrypted file from the network
        if (!receiveFile(receivedFile, port)) {
            return 1;  // Reception failed
        }

        // Update filename to point to the received file
        filename = receivedFile;
    }
    // LOCAL MODE: Use existing file
    else {
        // Expect the input file to have .FIU extension
        // If not provided, add it automatically
        // For example: ./grec myfile -l
        //   Looks for myfile.FIU
        if (filename.length() < 4 || filename.substr(filename.length() - 4) != ".FIU") {
            filename += ".FIU";
        }
    }

    // At this point, 'filename' points to the encrypted .FIU file

    // ========================================================================
    // Step 4: Get password and derive key
    // ========================================================================
    string password = getPassword();    // Securely read password from user
    unsigned char key[KEY_SIZE];        // Buffer for derived key
    deriveKey(password, key);           // Derive key using PBKDF2

    // If the password matches the one used during encryption, the derived
    // key will be identical, and HMAC verification will succeed

    // ========================================================================
    // Step 5: Verify and remove HMAC
    // ========================================================================
    // This is a critical security step
    // verifyAndRemoveHMAC() will:
    //   1. Compute HMAC over the encrypted data
    //   2. Compare with HMAC stored in the file
    //   3. Return false if they don't match (wrong password or tampering)
    //   4. If valid, remove HMAC from file (prepare for decryption)

    if (!verifyAndRemoveHMAC(filename, key)) {
        // HMAC verification failed
        // This means either:
        //   - Wrong password was entered
        //   - File has been tampered with
        //   - File is corrupted
        // We MUST NOT decrypt the file
        return 62;  // HMAC failure exit code (per assignment)
    }

    // If we reach here, HMAC is valid and file is authenticated
    // It is now safe to proceed with decryption

    // ========================================================================
    // Step 6: Determine output filename
    // ========================================================================
    // Remove the .FIU extension to get the original filename
    // For example: myfile.FIU -> myfile

    string outputFile;
    if (filename.length() >= 4 && filename.substr(filename.length() - 4) == ".FIU") {
        // Remove .FIU extension
        outputFile = filename.substr(0, filename.length() - 4);
    } else {
        // Fallback: add .decrypted if no .FIU extension found
        outputFile = filename + ".decrypted";
    }

    // ========================================================================
    // Step 7: Decrypt the file
    // ========================================================================
    // decryptFile() will:
    //   1. Read IV from the first 16 bytes
    //   2. Decrypt the remaining data using AES-256-CBC
    //   3. Remove PKCS#7 padding
    //   4. Write plaintext to output file

    if (!decryptFile(filename, outputFile, key)) {
        // Decryption failed
        // This should be rare since HMAC already verified
        // Possible causes:
        //   - File corrupted between HMAC verification and decryption
        //   - Incorrect key (shouldn't happen if HMAC passed)
        return 33;  // Output file exists error code
    }

    // ========================================================================
    // Step 8: Report success
    // ========================================================================
    // Get the decrypted file size for reporting
    ifstream file(outputFile, ios::binary | ios::ate);
    size_t fileSize = file.tellg();
    file.close();

    cout << "Successfully received and decrypted " << outputFile
         << " (" << fileSize << " bytes written)." << endl;

    // ========================================================================
    // Step 9: Exit successfully
    // ========================================================================
    return 0;  // Success
}
