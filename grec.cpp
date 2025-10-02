/*
 * grec.cpp - File reception and decryption utility
 *
 * This program receives and decrypts files encrypted by gsend.
 * It can either receive files over the network or decrypt local files.
 *
 * Usage: grec <filename> [-d <port>][-l]
 *
 * Key components:
 * - PBKDF2 for key derivation from password
 * - AES-256-CBC for decryption
 * - HMAC-SHA512 verification (Encrypt-then-MAC)
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <termios.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

using namespace std;

// Constants for cryptographic operations
#define KEY_SIZE 32        // 256 bits for AES-256
#define IV_SIZE 16         // 128 bits for AES block size
#define HMAC_SIZE 64       // 512 bits for SHA-512
#define PBKDF2_ITERATIONS 4096
#define SALT "KCl"

/*
 * getPassword() - Securely read password from stdin without echoing
 * Returns: password string
 */
string getPassword() {
    struct termios oldt, newt;
    string password;

    // Disable echo
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    cout << "Password: ";
    getline(cin, password);
    cout << endl;

    // Re-enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return password;
}

/*
 * deriveKey() - Derive encryption key from password using PBKDF2
 *
 * Parameters:
 *   password - user-provided password
 *   key - output buffer for derived key (must be KEY_SIZE bytes)
 *
 * Uses SHA-512 with 4096 iterations and "KCl" as salt
 */
void deriveKey(const string& password, unsigned char* key) {
    PKCS5_PBKDF2_HMAC(
        password.c_str(), password.length(),
        (const unsigned char*)SALT, strlen(SALT),
        PBKDF2_ITERATIONS,
        EVP_sha512(),
        KEY_SIZE,
        key
    );

    // Print key in hexadecimal for grading purposes
    cout << "Key: ";
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02X ", key[i]);
    }
    cout << endl;
}

/*
 * verifyAndRemoveHMAC() - Verify HMAC and remove it from encrypted file
 *
 * Parameters:
 *   filename - path to encrypted file with HMAC appended
 *   key - HMAC key (same as encryption key)
 *
 * Returns: true if HMAC is valid, false otherwise
 *
 * This function reads the file, extracts the HMAC from the end,
 * computes the HMAC of the remaining data, and compares.
 * If valid, it removes the HMAC from the file.
 */
bool verifyAndRemoveHMAC(const string& filename, const unsigned char* key) {
    // Read entire file
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open file for HMAC verification" << endl;
        return false;
    }

    inFile.seekg(0, ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    if (fileSize < HMAC_SIZE) {
        cerr << "Error: File too small to contain HMAC" << endl;
        return false;
    }

    // Read file data and extract HMAC
    size_t dataSize = fileSize - HMAC_SIZE;
    unsigned char* data = new unsigned char[dataSize];
    unsigned char fileHmac[HMAC_SIZE];

    inFile.read((char*)data, dataSize);
    inFile.read((char*)fileHmac, HMAC_SIZE);
    inFile.close();

    // Compute HMAC of encrypted data
    unsigned char computedHmac[HMAC_SIZE];
    unsigned int hmacLen;

    HMAC(EVP_sha512(), key, KEY_SIZE, data, dataSize, computedHmac, &hmacLen);

    // Compare HMACs
    bool valid = (memcmp(fileHmac, computedHmac, HMAC_SIZE) == 0);

    if (!valid) {
        cerr << "Error: HMAC verification failed" << endl;
        delete[] data;
        return false;
    }

    // Write file without HMAC
    ofstream outFile(filename, ios::binary | ios::trunc);
    if (!outFile) {
        cerr << "Error: Cannot rewrite file without HMAC" << endl;
        delete[] data;
        return false;
    }
    outFile.write((char*)data, dataSize);
    outFile.close();

    delete[] data;
    return true;
}

/*
 * decryptFile() - Decrypt file contents using AES-256-CBC
 *
 * Parameters:
 *   inputFile - path to encrypted file
 *   outputFile - path to write decrypted output
 *   key - decryption key (KEY_SIZE bytes)
 *
 * Returns: true on success, false on failure
 *
 * The IV is read from the beginning of the encrypted file.
 */
bool decryptFile(const string& inputFile, const string& outputFile,
                 const unsigned char* key) {
    // Check if output file already exists
    ifstream testOut(outputFile);
    if (testOut.good()) {
        cerr << "Error: Output file already exists" << endl;
        testOut.close();
        return false;
    }
    testOut.close();

    // Open input file and read IV
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open input file" << endl;
        return false;
    }

    unsigned char iv[IV_SIZE];
    inFile.read((char*)iv, IV_SIZE);
    if (inFile.gcount() != IV_SIZE) {
        cerr << "Error: Failed to read IV" << endl;
        return false;
    }

    // Open output file
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot create output file" << endl;
        return false;
    }

    // Initialize decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Failed to create cipher context" << endl;
        return false;
    }

    // Initialize AES-256-CBC decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error: Failed to initialize decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Decrypt file in chunks
    unsigned char inBuf[4096];
    unsigned char outBuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    while (inFile.read((char*)inBuf, sizeof(inBuf)) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        if (EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            cerr << "Error: Decryption failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write((char*)outBuf, outLen);
    }

    // Finalize decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        cerr << "Error: Decryption finalization failed (possibly wrong password)" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write((char*)outBuf, outLen);

    EVP_CIPHER_CTX_free(ctx);
    inFile.close();
    outFile.close();

    return true;
}

/*
 * receiveFile() - Receive file over network on specified port
 *
 * Parameters:
 *   filename - path to save received file
 *   port - port number to listen on
 *
 * Returns: true on success, false on failure
 *
 * Acts as a server, listening for incoming connections.
 * Receives file data and saves to specified filename.
 */
bool receiveFile(const string& filename, int port) {
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Cannot create socket" << endl;
        return false;
    }

    // Set socket options to allow reuse
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error: setsockopt failed" << endl;
        close(sockfd);
        return false;
    }

    // Set up server address
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port = htons(port);

    // Bind socket
    if (::bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        cerr << "Error: Bind failed" << endl;
        close(sockfd);
        return false;
    }

    // Listen for connections
    if (listen(sockfd, 1) < 0) {
        cerr << "Error: Listen failed" << endl;
        close(sockfd);
        return false;
    }

    cout << "Waiting for connections." << endl;

    // Accept connection
    struct sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
    int clientfd = accept(sockfd, (struct sockaddr*)&clientAddr, &clientLen);
    if (clientfd < 0) {
        cerr << "Error: Accept failed" << endl;
        close(sockfd);
        return false;
    }

    cout << "Inbound file." << endl;

    // Receive file
    ofstream outFile(filename, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot create output file" << endl;
        close(clientfd);
        close(sockfd);
        return false;
    }

    char buffer[4096];
    ssize_t bytesReceived;
    while ((bytesReceived = recv(clientfd, buffer, sizeof(buffer), 0)) > 0) {
        outFile.write(buffer, bytesReceived);
    }

    outFile.close();

    // Send acknowledgment
    const char* ack = "Successfully received";
    send(clientfd, ack, strlen(ack), 0);

    close(clientfd);
    close(sockfd);

    return true;
}

/*
 * main() - Entry point for grec program
 *
 * Returns:
 *   0 - success
 *   62 - HMAC verification failed
 *   33 - output file already exists
 *   1 - other errors
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <filename> [-d <port>][-l]" << endl;
        return 1;
    }

    string filename = argv[1];
    bool networkMode = false;
    int port = 0;

    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            networkMode = true;
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0) {
            networkMode = false;
        }
    }

    // Network mode: receive file first
    if (networkMode && port > 0) {
        string receivedFile = filename + ".FIU";
        if (!receiveFile(receivedFile, port)) {
            return 1;
        }
        filename = receivedFile;
    } else {
        // Local mode: expect .FIU file
        if (filename.length() < 4 || filename.substr(filename.length() - 4) != ".FIU") {
            filename += ".FIU";
        }
    }

    // Get password and derive key
    string password = getPassword();
    unsigned char key[KEY_SIZE];
    deriveKey(password, key);

    // Verify and remove HMAC
    if (!verifyAndRemoveHMAC(filename, key)) {
        return 62;
    }

    // Determine output filename (remove .FIU extension)
    string outputFile;
    if (filename.length() >= 4 && filename.substr(filename.length() - 4) == ".FIU") {
        outputFile = filename.substr(0, filename.length() - 4);
    } else {
        outputFile = filename + ".decrypted";
    }

    // Decrypt file
    if (!decryptFile(filename, outputFile, key)) {
        return 33;
    }

    // Get output file size
    ifstream file(outputFile, ios::binary | ios::ate);
    size_t fileSize = file.tellg();
    file.close();

    cout << "Successfully received and decrypted " << outputFile
         << " (" << fileSize << " bytes written)." << endl;

    return 0;
}
