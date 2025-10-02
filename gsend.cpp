/*
 * gsend.cpp - File encryption and transmission utility
 *
 * This program encrypts files using AES-256-CBC with HMAC-SHA512 authentication.
 * It can either save encrypted files locally or transmit them over the network.
 *
 * Usage: gsend <input file> [-d <IP-addr:port>][-l]
 *
 * Key components:
 * - PBKDF2 for key derivation from password
 * - AES-256-CBC for encryption
 * - HMAC-SHA512 for authentication (Encrypt-then-MAC)
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
#include <openssl/rand.h>
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
 * encryptFile() - Encrypt file contents using AES-256-CBC
 *
 * Parameters:
 *   inputFile - path to file to encrypt
 *   outputFile - path to write encrypted output
 *   key - encryption key (KEY_SIZE bytes)
 *   iv - initialization vector (IV_SIZE bytes, will be generated)
 *
 * Returns: true on success, false on failure
 *
 * The IV is prepended to the encrypted output for use during decryption
 */
bool encryptFile(const string& inputFile, const string& outputFile,
                 const unsigned char* key, unsigned char* iv) {
    // Check if output file already exists
    ifstream testOut(outputFile);
    if (testOut.good()) {
        cerr << "Error: Output file already exists" << endl;
        testOut.close();
        return false;
    }
    testOut.close();

    // Generate random IV
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        cerr << "Error: Failed to generate IV" << endl;
        return false;
    }

    // Open input file
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open input file" << endl;
        return false;
    }

    // Open output file and write IV first
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot create output file" << endl;
        return false;
    }
    outFile.write((char*)iv, IV_SIZE);

    // Initialize encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Failed to create cipher context" << endl;
        return false;
    }

    // Initialize AES-256-CBC encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error: Failed to initialize encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Encrypt file in chunks
    unsigned char inBuf[4096];
    unsigned char outBuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    while (inFile.read((char*)inBuf, sizeof(inBuf)) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            cerr << "Error: Encryption failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write((char*)outBuf, outLen);
    }

    // Finalize encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        cerr << "Error: Encryption finalization failed" << endl;
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
 * addHMAC() - Compute and append HMAC-SHA512 to encrypted file
 *
 * Parameters:
 *   filename - path to encrypted file
 *   key - HMAC key (same as encryption key)
 *
 * Returns: true on success, false on failure
 *
 * Implements Encrypt-then-MAC: HMAC is computed over encrypted data
 * and appended to the file.
 */
bool addHMAC(const string& filename, const unsigned char* key) {
    // Read entire encrypted file
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open file for HMAC" << endl;
        return false;
    }

    inFile.seekg(0, ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    unsigned char* data = new unsigned char[fileSize];
    inFile.read((char*)data, fileSize);
    inFile.close();

    // Compute HMAC-SHA512
    unsigned char hmac[HMAC_SIZE];
    unsigned int hmacLen;

    HMAC(EVP_sha512(), key, KEY_SIZE, data, fileSize, hmac, &hmacLen);

    // Append HMAC to file
    ofstream outFile(filename, ios::binary | ios::app);
    if (!outFile) {
        cerr << "Error: Cannot append HMAC" << endl;
        delete[] data;
        return false;
    }
    outFile.write((char*)hmac, HMAC_SIZE);
    outFile.close();

    delete[] data;
    return true;
}

/*
 * sendFile() - Transmit file over network to specified IP:port
 *
 * Parameters:
 *   filename - path to file to send
 *   ipAddr - destination IP address
 *   port - destination port number
 *
 * Returns: true on success, false on failure
 */
bool sendFile(const string& filename, const string& ipAddr, int port) {
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Cannot create socket" << endl;
        return false;
    }

    // Set up server address
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, ipAddr.c_str(), &servAddr.sin_addr) <= 0) {
        cerr << "Error: Invalid IP address" << endl;
        close(sockfd);
        return false;
    }

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        cerr << "Error: Connection failed" << endl;
        close(sockfd);
        return false;
    }

    cout << "Transmitting to " << ipAddr << ":" << port << endl;

    // Send file
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Cannot open file for transmission" << endl;
        close(sockfd);
        return false;
    }

    char buffer[4096];
    while (inFile.read(buffer, sizeof(buffer)) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        if (send(sockfd, buffer, bytesRead, 0) < 0) {
            cerr << "Error: Send failed" << endl;
            close(sockfd);
            return false;
        }
    }

    inFile.close();

    // Wait for acknowledgment
    char ack[100];
    int n = recv(sockfd, ack, sizeof(ack) - 1, 0);
    if (n > 0) {
        ack[n] = '\0';
        cout << ack << endl;
    }

    close(sockfd);
    return true;
}

/*
 * main() - Entry point for gsend program
 *
 * Returns:
 *   0 - success
 *   33 - output file already exists
 *   1 - other errors
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <input file> [-d <IP-addr:port>][-l]" << endl;
        return 1;
    }

    string inputFile = argv[1];
    bool networkMode = false;
    string destination;

    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            networkMode = true;
            destination = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0) {
            networkMode = false;
        }
    }

    // Get password and derive key
    string password = getPassword();
    unsigned char key[KEY_SIZE];
    deriveKey(password, key);

    // Generate output filename
    string outputFile = inputFile + ".FIU";

    // Encrypt file
    unsigned char iv[IV_SIZE];
    if (!encryptFile(inputFile, outputFile, key, iv)) {
        return 33;
    }

    // Add HMAC
    if (!addHMAC(outputFile, key)) {
        return 1;
    }

    // Get file size
    ifstream file(outputFile, ios::binary | ios::ate);
    size_t fileSize = file.tellg();
    file.close();

    cout << "Successfully encrypted " << inputFile << " to " << outputFile
         << " (" << fileSize << " bytes written)." << endl;

    // Send over network if requested
    if (networkMode && !destination.empty()) {
        size_t colonPos = destination.find(':');
        if (colonPos == string::npos) {
            cerr << "Error: Invalid destination format (use IP:port)" << endl;
            return 1;
        }

        string ipAddr = destination.substr(0, colonPos);
        int port = stoi(destination.substr(colonPos + 1));

        if (!sendFile(outputFile, ipAddr, port)) {
            return 1;
        }
    }

    return 0;
}
