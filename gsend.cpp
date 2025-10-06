/*
 * ============================================================================
 * gsend.cpp - File Encryption and Transmission Utility
 * ============================================================================
 *
 * PROGRAM DESCRIPTION:
 * This program provides secure file encryption using industry-standard
 * cryptographic libraries. It implements the Encrypt-then-MAC paradigm,
 * which is considered the most secure approach for authenticated encryption.
 *
 * FUNCTIONALITY:
 * - Encrypts files using AES-256 in CBC mode
 * - Derives encryption keys from passwords using PBKDF2
 * - Authenticates encrypted data with HMAC-SHA512
 * - Supports both local file encryption and network transmission
 *
 * USAGE:
 *   gsend <input file> [-d <IP-addr:port>][-l]
 *
 * OPTIONS:
 *   -l              Local mode: encrypt file and save as <filename>.FIU
 *   -d IP:port      Network mode: encrypt and transmit to specified address
 *
 * SECURITY FEATURES:
 * - Password-based key derivation (PBKDF2 with SHA-512, 4096 iterations)
 * - AES-256-CBC encryption with cryptographically random IV
 * - HMAC-SHA512 for message authentication (Encrypt-then-MAC)
 * - Secure password input (no echo to terminal)
 *
 * FILE FORMAT (encrypted .FIU files):
 *   [IV (16 bytes)][Encrypted Data (variable)][HMAC (64 bytes)]
 *
 * CRYPTOGRAPHIC PARAMETERS:
 * - Key derivation: PBKDF2-HMAC-SHA512, 4096 iterations, salt="KCl"
 * - Encryption: AES-256-CBC (256-bit key, 128-bit IV)
 * - MAC: HMAC-SHA512 (512-bit output)
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
#include <openssl/rand.h> // For cryptographically secure random numbers
#include <openssl/hmac.h> // For HMAC operations
#include <openssl/sha.h>  // For SHA hash functions

using namespace std;

// ============================================================================
// CRYPTOGRAPHIC CONSTANTS
// ============================================================================

/*
 * KEY_SIZE: Size of the encryption key in bytes
 * - AES-256 requires a 256-bit (32-byte) key
 * - This key is derived from the user's password using PBKDF2
 */
#define KEY_SIZE 32

/*
 * IV_SIZE: Size of the Initialization Vector in bytes
 * - AES uses a 128-bit (16-byte) block size regardless of key size
 * - The IV ensures that identical plaintexts encrypt to different ciphertexts
 * - A new random IV is generated for each encryption operation
 */
#define IV_SIZE 16

/*
 * HMAC_SIZE: Size of the HMAC output in bytes
 * - SHA-512 produces a 512-bit (64-byte) hash
 * - This is appended to the encrypted file for authentication
 */
#define HMAC_SIZE 64

/*
 * PBKDF2_ITERATIONS: Number of iterations for key derivation
 * - Higher iteration counts increase resistance to brute-force attacks
 * - 4096 iterations is specified by the assignment
 * - Modern standards recommend 100,000+ iterations for production use
 */
#define PBKDF2_ITERATIONS 4096

/*
 * SALT: Fixed salt value for PBKDF2
 * - Normally, salts should be random and unique per password
 * - For this assignment, a fixed salt "KCl" is used for simplicity
 * - In production, use a randomly generated salt stored with the ciphertext
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
 *   - The password is stored in memory as a std::string
 *   - For production use, consider using secure memory (mlock/memset)
 *   - The password should be cleared from memory after key derivation
 */
string getPassword() {
    struct termios oldt, newt;  // Terminal settings structures
    string password;             // Password storage

    // Step 1: Get current terminal settings
    // tcgetattr() retrieves the parameters associated with the terminal
    // STDIN_FILENO is the file descriptor for standard input
    tcgetattr(STDIN_FILENO, &oldt);

    // Step 2: Copy old settings and modify to disable echo
    newt = oldt;
    newt.c_lflag &= ~ECHO;  // Clear the ECHO flag using bitwise AND with NOT

    // Step 3: Apply new terminal settings immediately (TCSANOW)
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Step 4: Prompt for and read password
    cout << "Password: ";
    getline(cin, password);  // Read entire line (allows spaces in password)
    cout << endl;            // Print newline since echo is disabled

    // Step 5: Restore original terminal settings
    // This ensures the terminal behaves normally after password entry
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
 *   Derives a cryptographic key from a user-supplied password using PBKDF2
 *   (Password-Based Key Derivation Function 2). This transforms a potentially
 *   weak password into a strong encryption key.
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
 *   PBKDF2 applies a pseudorandom function (PRF) repeatedly to derive keys.
 *   The iteration count makes brute-force attacks computationally expensive.
 *   Formula: DK = PBKDF2(PRF, Password, Salt, c, dkLen)
 *   Where:
 *     - PRF = HMAC-SHA512
 *     - c = iteration count (4096)
 *     - dkLen = desired key length (32 bytes)
 *
 * OUTPUT:
 *   Prints the derived key in hexadecimal format for grading/verification
 */
void deriveKey(const string& password, unsigned char* key) {
    // Call OpenSSL's PBKDF2 implementation
    // PKCS5_PBKDF2_HMAC is the standard function for PBKDF2 key derivation
    PKCS5_PBKDF2_HMAC(
        password.c_str(),              // Password string (null-terminated)
        password.length(),             // Password length in bytes
        (const unsigned char*)SALT,    // Salt value (cast to unsigned char*)
        strlen(SALT),                  // Salt length in bytes
        PBKDF2_ITERATIONS,             // Number of iterations (4096)
        EVP_sha512(),                  // Hash function (SHA-512)
        KEY_SIZE,                      // Desired output length (32 bytes)
        key                            // Output buffer for derived key
    );

    // Print the derived key in hexadecimal format
    // This is required by the assignment for grading purposes
    // Format: "Key: XX XX XX ... XX" where XX is a 2-digit hex value
    cout << "Key: ";
    for (int i = 0; i < KEY_SIZE; i++) {
        // %02X formats as 2-digit uppercase hex with leading zero if needed
        printf("%02X ", key[i]);
    }
    cout << endl;
}

// ============================================================================
// FUNCTION: encryptFile()
// ============================================================================

/*
 * FUNCTION: encryptFile
 *
 * PURPOSE:
 *   Encrypts a file using AES-256 in CBC (Cipher Block Chaining) mode.
 *   The encrypted output includes a prepended IV for use during decryption.
 *
 * ALGORITHM:
 *   1. Check if output file already exists (error if it does)
 *   2. Generate a cryptographically random IV
 *   3. Write IV to output file (first 16 bytes)
 *   4. Initialize AES-256-CBC encryption context
 *   5. Read input file in chunks and encrypt each chunk
 *   6. Finalize encryption (handles PKCS#7 padding)
 *   7. Close files and cleanup
 *
 * PARAMETERS:
 *   inputFile  - Path to the file to encrypt
 *   outputFile - Path where encrypted file will be written
 *   key        - Encryption key (32 bytes from PBKDF2)
 *   iv         - Buffer to store generated IV (16 bytes, output parameter)
 *
 * RETURN VALUE:
 *   true  - Encryption succeeded
 *   false - Encryption failed (error message printed to stderr)
 *
 * FILE FORMAT:
 *   Output file structure: [IV][Encrypted Data]
 *   - IV is prepended so decryption can use it
 *   - Encrypted data includes PKCS#7 padding
 *
 * SECURITY NOTES:
 *   - Uses CBC mode (requires IV for security)
 *   - IV is generated using cryptographically secure random number generator
 *   - PKCS#7 padding is automatically applied by OpenSSL
 *   - Each encryption uses a unique IV (never reuse IVs with same key!)
 *
 * ERROR HANDLING:
 *   - Returns false if output file exists (prevents accidental overwrite)
 *   - Returns false if IV generation fails
 *   - Returns false if file I/O fails
 *   - Returns false if encryption initialization or processing fails
 */
bool encryptFile(const string& inputFile, const string& outputFile,
                 const unsigned char* key, unsigned char* iv) {

    // ========================================================================
    // Step 1: Check if output file already exists
    // ========================================================================
    // The assignment requires returning error code 33 if output exists
    // We check this first before doing any work
    ifstream testOut(outputFile);
    if (testOut.good()) {
        cerr << "Error: Output file already exists" << endl;
        testOut.close();
        return false;  // Caller will return exit code 33
    }
    testOut.close();

    // ========================================================================
    // Step 2: Generate cryptographically random IV
    // ========================================================================
    // The IV must be random and unique for each encryption operation
    // RAND_bytes() uses OpenSSL's CSPRNG (Cryptographically Secure PRNG)
    // Returns 1 on success, 0 or -1 on failure
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        cerr << "Error: Failed to generate IV" << endl;
        return false;
    }

    // ========================================================================
    // Step 3: Open input file for reading
    // ========================================================================
    // ios::binary ensures we read the file in binary mode
    // This is critical for non-text files (images, executables, etc.)
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open input file" << endl;
        return false;
    }

    // ========================================================================
    // Step 4: Open output file and write IV
    // ========================================================================
    // The IV is written as the first 16 bytes of the output file
    // During decryption, grec will read this IV first
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot create output file" << endl;
        return false;
    }
    outFile.write((char*)iv, IV_SIZE);

    // ========================================================================
    // Step 5: Initialize encryption context
    // ========================================================================
    // OpenSSL uses an EVP_CIPHER_CTX structure to maintain encryption state
    // This must be allocated, initialized, used, and then freed
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Failed to create cipher context" << endl;
        return false;
    }

    // Initialize the encryption operation with AES-256-CBC
    // Parameters:
    //   - ctx: the context structure
    //   - EVP_aes_256_cbc(): specifies AES-256 in CBC mode
    //   - NULL: use default engine (no hardware acceleration specified)
    //   - key: the encryption key (32 bytes)
    //   - iv: the initialization vector (16 bytes)
    // Returns 1 on success, 0 on failure
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error: Failed to initialize encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // ========================================================================
    // Step 6: Encrypt file in chunks
    // ========================================================================
    // We process the file in 4KB chunks for memory efficiency
    // This allows encryption of files larger than available RAM
    unsigned char inBuf[4096];                       // Input buffer
    unsigned char outBuf[4096 + EVP_MAX_BLOCK_LENGTH]; // Output buffer
    int outLen;                                      // Bytes written per chunk

    // EVP_MAX_BLOCK_LENGTH accounts for padding that may be added
    // CBC mode works on 16-byte blocks, so output can be up to 16 bytes longer

    // Read file in chunks until EOF
    while (inFile.read((char*)inBuf, sizeof(inBuf)) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();  // Actual bytes read (may be < 4096)

        // Encrypt this chunk
        // EVP_EncryptUpdate can be called multiple times
        // It processes input data and produces encrypted output
        if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            cerr << "Error: Encryption failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Write encrypted chunk to output file
        outFile.write((char*)outBuf, outLen);
    }

    // ========================================================================
    // Step 7: Finalize encryption
    // ========================================================================
    // EVP_EncryptFinal_ex handles the final block and padding
    // PKCS#7 padding is automatically applied:
    //   - If data is block-aligned, a full block of padding is added
    //   - Otherwise, padding bytes are added to complete the final block
    //   - Each padding byte contains the number of padding bytes added
    // Example: if 3 padding bytes needed, append [03 03 03]
    if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        cerr << "Error: Encryption finalization failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write((char*)outBuf, outLen);

    // ========================================================================
    // Step 8: Cleanup
    // ========================================================================
    EVP_CIPHER_CTX_free(ctx);  // Free encryption context
    inFile.close();             // Close input file
    outFile.close();            // Close output file

    return true;  // Success
}

// ============================================================================
// FUNCTION: addHMAC()
// ============================================================================

/*
 * FUNCTION: addHMAC
 *
 * PURPOSE:
 *   Computes an HMAC-SHA512 authentication tag over the encrypted file
 *   and appends it to the file. This implements the Encrypt-then-MAC
 *   construction, which is cryptographically secure.
 *
 * ALGORITHM:
 *   1. Read the entire encrypted file into memory
 *   2. Compute HMAC-SHA512 over the encrypted data
 *   3. Append the 64-byte HMAC to the end of the file
 *
 * PARAMETERS:
 *   filename - Path to the encrypted file
 *   key      - HMAC key (same as encryption key per assignment)
 *
 * RETURN VALUE:
 *   true  - HMAC successfully computed and appended
 *   false - Operation failed (error message printed to stderr)
 *
 * CRYPTOGRAPHIC DETAILS:
 *   - MAC algorithm: HMAC-SHA512
 *   - Key: Same 32-byte key used for encryption
 *   - Input: IV + encrypted data (entire file contents)
 *   - Output: 64-byte HMAC tag
 *
 * ENCRYPT-THEN-MAC:
 *   This is the recommended authenticated encryption construction.
 *   Alternatives:
 *     - MAC-then-Encrypt: Vulnerable to padding oracle attacks
 *     - Encrypt-and-MAC: MAC doesn't cover ciphertext
 *     - Encrypt-then-MAC: Secure (what we use)
 *
 * SECURITY NOTES:
 *   - HMAC prevents tampering with the ciphertext
 *   - Any modification to the encrypted file will be detected
 *   - Using the same key for encryption and MAC is acceptable for HMAC
 *   - In production, consider using dedicated keys (derived separately)
 *
 * FILE FORMAT AFTER THIS FUNCTION:
 *   [IV (16 bytes)][Encrypted Data (variable)][HMAC (64 bytes)]
 */
bool addHMAC(const string& filename, const unsigned char* key) {

    // ========================================================================
    // Step 1: Read entire encrypted file
    // ========================================================================
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open file for HMAC" << endl;
        return false;
    }

    // Determine file size by seeking to end
    inFile.seekg(0, ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);  // Seek back to beginning

    // Allocate buffer and read entire file
    // Note: For very large files, consider streaming HMAC computation
    unsigned char* data = new unsigned char[fileSize];
    inFile.read((char*)data, fileSize);
    inFile.close();

    // ========================================================================
    // Step 2: Compute HMAC-SHA512
    // ========================================================================
    unsigned char hmac[HMAC_SIZE];  // Buffer for HMAC output
    unsigned int hmacLen;           // Actual HMAC length (will be 64)

    // HMAC() is a convenience function that computes HMAC in one call
    // Parameters:
    //   - EVP_sha512(): Use SHA-512 as the hash function
    //   - key: HMAC key (32 bytes)
    //   - KEY_SIZE: Length of HMAC key
    //   - data: Input data to authenticate (encrypted file)
    //   - fileSize: Length of input data
    //   - hmac: Output buffer for HMAC tag
    //   - hmacLen: Pointer to store actual HMAC length
    // Returns pointer to hmac buffer (or NULL on error)
    HMAC(EVP_sha512(), key, KEY_SIZE, data, fileSize, hmac, &hmacLen);

    // ========================================================================
    // Step 3: Append HMAC to file
    // ========================================================================
    // Open file in append mode (ios::app)
    // This positions the write pointer at the end of the file
    ofstream outFile(filename, ios::binary | ios::app);
    if (!outFile) {
        cerr << "Error: Cannot append HMAC" << endl;
        delete[] data;
        return false;
    }

    // Write all 64 bytes of the HMAC
    outFile.write((char*)hmac, HMAC_SIZE);
    outFile.close();

    // ========================================================================
    // Step 4: Cleanup
    // ========================================================================
    delete[] data;  // Free the file buffer

    return true;  // Success
}

// ============================================================================
// FUNCTION: sendFile()
// ============================================================================

/*
 * FUNCTION: sendFile
 *
 * PURPOSE:
 *   Transmits an encrypted file over a TCP network connection to a
 *   specified IP address and port. The receiver should be running grec
 *   in daemon mode (-d) on the specified port.
 *
 * ALGORITHM:
 *   1. Create a TCP socket
 *   2. Configure server address structure (IP and port)
 *   3. Establish connection to server
 *   4. Read encrypted file and send over socket
 *   5. Wait for acknowledgment from receiver
 *   6. Close connection
 *
 * PARAMETERS:
 *   filename - Path to the encrypted file to transmit
 *   ipAddr   - Destination IP address (e.g., "192.168.1.100")
 *   port     - Destination port number (e.g., 8888)
 *
 * RETURN VALUE:
 *   true  - File successfully transmitted
 *   false - Transmission failed (error message printed to stderr)
 *
 * NETWORK PROTOCOL:
 *   - Transport: TCP (reliable, ordered delivery)
 *   - File is sent as a continuous stream of bytes
 *   - No explicit framing (receiver reads until connection closes)
 *   - Simple acknowledgment message received after transmission
 *
 * SECURITY NOTES:
 *   - The file is already encrypted, so network transmission is secure
 *   - TCP provides no authentication (man-in-the-middle attacks possible)
 *   - For production use, consider TLS/SSL for the network layer
 *   - No encryption of network traffic itself (data is already encrypted)
 *
 * ERROR HANDLING:
 *   - Socket creation failure
 *   - Invalid IP address format
 *   - Connection refused (receiver not listening)
 *   - File read errors
 *   - Network transmission errors
 */
bool sendFile(const string& filename, const string& ipAddr, int port) {

    // ========================================================================
    // Step 1: Create a socket
    // ========================================================================
    // socket() creates an endpoint for communication
    // Parameters:
    //   - AF_INET: IPv4 Internet protocols
    //   - SOCK_STREAM: TCP (connection-oriented, reliable, byte stream)
    //   - 0: Protocol (0 = default for the socket type, i.e., TCP)
    // Returns: socket file descriptor, or -1 on error
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Cannot create socket" << endl;
        return false;
    }

    // ========================================================================
    // Step 2: Configure server address structure
    // ========================================================================
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));  // Zero out structure

    servAddr.sin_family = AF_INET;           // IPv4
    servAddr.sin_port = htons(port);         // Convert port to network byte order

    // htons() = Host TO Network Short
    // Network byte order is big-endian; host may be little-endian
    // This ensures portability across different architectures

    // Convert IP address from string to binary form
    // inet_pton() = Internet Protocol to Network
    // Parameters:
    //   - AF_INET: IPv4 address family
    //   - ipAddr.c_str(): IP address string (e.g., "192.168.1.1")
    //   - &servAddr.sin_addr: Destination for binary IP address
    // Returns: 1 on success, 0 if invalid format, -1 on error
    if (inet_pton(AF_INET, ipAddr.c_str(), &servAddr.sin_addr) <= 0) {
        cerr << "Error: Invalid IP address" << endl;
        close(sockfd);
        return false;
    }

    // ========================================================================
    // Step 3: Connect to server
    // ========================================================================
    // connect() initiates a TCP connection to the server
    // This performs the TCP 3-way handshake (SYN, SYN-ACK, ACK)
    // Parameters:
    //   - sockfd: Socket file descriptor
    //   - (struct sockaddr*)&servAddr: Server address (cast to generic type)
    //   - sizeof(servAddr): Size of address structure
    // Returns: 0 on success, -1 on error
    if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        cerr << "Error: Connection failed" << endl;
        close(sockfd);
        return false;
    }

    cout << "Transmitting to " << ipAddr << ":" << port << endl;

    // ========================================================================
    // Step 4: Send file over network
    // ========================================================================
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open file for transmission" << endl;
        close(sockfd);
        return false;
    }

    // Read and send file in chunks
    char buffer[4096];
    while (inFile.read(buffer, sizeof(buffer)) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();

        // send() transmits data over the socket
        // Parameters:
        //   - sockfd: Socket file descriptor
        //   - buffer: Data to send
        //   - bytesRead: Number of bytes to send
        //   - 0: Flags (none specified)
        // Returns: Number of bytes sent, or -1 on error
        // Note: send() may send fewer bytes than requested (partial send)
        // For robustness, should check return value and retry if needed
        if (send(sockfd, buffer, bytesRead, 0) < 0) {
            cerr << "Error: Send failed" << endl;
            close(sockfd);
            return false;
        }
    }

    inFile.close();

    // ========================================================================
    // Step 5: Receive acknowledgment
    // ========================================================================
    // Wait for a simple acknowledgment message from the receiver
    // This confirms that the file was received successfully
    char ack[100];
    int n = recv(sockfd, ack, sizeof(ack) - 1, 0);
    if (n > 0) {
        ack[n] = '\0';  // Null-terminate the string
        cout << ack << endl;
    }

    // ========================================================================
    // Step 6: Cleanup
    // ========================================================================
    close(sockfd);  // Close socket

    return true;  // Success
}

// ============================================================================
// FUNCTION: main()
// ============================================================================

/*
 * FUNCTION: main
 *
 * PURPOSE:
 *   Entry point for the gsend program. Parses command-line arguments,
 *   orchestrates the encryption process, and optionally transmits the
 *   encrypted file over the network.
 *
 * COMMAND-LINE ARGUMENTS:
 *   argv[1]         - Input filename (required)
 *   -l              - Local mode (default)
 *   -d IP:port      - Network mode with destination address
 *
 * RETURN VALUES:
 *   0  - Success
 *   1  - General error (invalid arguments, encryption failed, etc.)
 *   33 - Output file already exists
 *
 * PROGRAM FLOW:
 *   1. Parse command-line arguments
 *   2. Get password from user (no echo)
 *   3. Derive encryption key using PBKDF2
 *   4. Encrypt input file with AES-256-CBC
 *   5. Compute and append HMAC-SHA512
 *   6. (Optional) Transmit encrypted file over network
 *
 * ERROR HANDLING:
 *   - Invalid command-line arguments
 *   - Encryption failures (handled by encryptFile)
 *   - HMAC computation failures (handled by addHMAC)
 *   - Network transmission failures (handled by sendFile)
 */
int main(int argc, char* argv[]) {

    // ========================================================================
    // Step 1: Validate command-line arguments
    // ========================================================================
    // Minimum requirement: program name + input filename
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <input file> [-d <IP-addr:port>][-l]" << endl;
        return 1;
    }

    // ========================================================================
    // Step 2: Parse command-line arguments
    // ========================================================================
    string inputFile = argv[1];        // First argument is always input file
    bool networkMode = false;          // Default to local mode
    string destination;                // IP:port string for network mode

    // Process optional flags
    // Iterate through remaining arguments looking for -d and -l flags
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            // Network mode: -d flag followed by IP:port
            networkMode = true;
            destination = argv[++i];  // Get next argument (IP:port)
        } else if (strcmp(argv[i], "-l") == 0) {
            // Local mode: -l flag explicitly specified
            networkMode = false;
        }
        // Unknown flags are silently ignored
    }

    // ========================================================================
    // Step 3: Get password and derive encryption key
    // ========================================================================
    string password = getPassword();    // Securely read password from user
    unsigned char key[KEY_SIZE];        // Buffer for derived key
    deriveKey(password, key);           // Derive key using PBKDF2

    // Security note: In production, clear password from memory after use
    // password.clear() or explicit memset

    // ========================================================================
    // Step 4: Generate output filename
    // ========================================================================
    // Encrypted files have the .FIU extension appended
    // Example: input.txt -> input.txt.FIU
    string outputFile = inputFile + ".FIU";

    // ========================================================================
    // Step 5: Encrypt the file
    // ========================================================================
    unsigned char iv[IV_SIZE];  // Buffer for generated IV

    // encryptFile() performs the actual encryption
    // It returns false if the output file already exists or encryption fails
    if (!encryptFile(inputFile, outputFile, key, iv)) {
        return 33;  // Output file exists error code (per assignment)
    }

    // ========================================================================
    // Step 6: Add HMAC for authentication
    // ========================================================================
    // Compute HMAC over the encrypted file and append it
    // This implements Encrypt-then-MAC for authenticated encryption
    if (!addHMAC(outputFile, key)) {
        return 1;  // HMAC computation failed
    }

    // ========================================================================
    // Step 7: Report success and file size
    // ========================================================================
    // Get the final encrypted file size (IV + ciphertext + HMAC)
    ifstream file(outputFile, ios::binary | ios::ate);
    size_t fileSize = file.tellg();
    file.close();

    cout << "Successfully encrypted " << inputFile << " to " << outputFile
         << " (" << fileSize << " bytes written)." << endl;

    // ========================================================================
    // Step 8: Optionally transmit over network
    // ========================================================================
    if (networkMode && !destination.empty()) {
        // Parse destination string "IP:port"
        size_t colonPos = destination.find(':');
        if (colonPos == string::npos) {
            cerr << "Error: Invalid destination format (use IP:port)" << endl;
            return 1;
        }

        // Extract IP address and port number
        string ipAddr = destination.substr(0, colonPos);
        int port = stoi(destination.substr(colonPos + 1));

        // Transmit the encrypted file
        if (!sendFile(outputFile, ipAddr, port)) {
            return 1;  // Transmission failed
        }
    }

    // ========================================================================
    // Step 9: Exit successfully
    // ========================================================================
    return 0;  // Success
}
