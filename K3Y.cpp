#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <openssl/evp.h>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
#endif

using namespace std;
using namespace chrono;

// ANSI Color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"

mutex coutMutex;
atomic<bool> passwordFound(false);
atomic<uint64_t> globalAttempts(0);
string foundPassword = "";

// Character sets
const char* CHARSET_NUMERIC = "0123456789";
const char* CHARSET_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const char* CHARSET_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char* CHARSET_ALPHANUM = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

void enableColors() {
    #ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    #endif
}

// Fast hex conversion (no string allocation)
inline void toHexFast(const unsigned char* data, size_t len, char* output) {
    static const char hexChars[] = "0123456789abcdef";
    for(size_t i = 0; i < len; i++) {
        output[i * 2] = hexChars[data[i] >> 4];
        output[i * 2 + 1] = hexChars[data[i] & 0x0F];
    }
    output[len * 2] = '\0';
}

// Fast integer power (no floating point)
inline uint64_t ipow(uint64_t base, int exp) {
    uint64_t result = 1;
    for(int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

// Fast number to string without allocation
inline int numToStr(uint64_t num, char* buf) {
    if(num == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }
    
    int len = 0;
    uint64_t temp = num;
    while(temp > 0) {
        len++;
        temp /= 10;
    }
    
    buf[len] = '\0';
    for(int i = len - 1; i >= 0; i--) {
        buf[i] = '0' + (num % 10);
        num /= 10;
    }
    return len;
}

// Generate password from index for FIXED length (fast)
inline void indexToPasswordFixed(uint64_t index, const char* charset, int charsetLen, int pwdLen, char* output) {
    for(int i = pwdLen - 1; i >= 0; i--) {
        output[i] = charset[index % charsetLen];
        index /= charsetLen;
    }
    output[pwdLen] = '\0';
}

// Worker for numeric passwords (OPTIMIZED)
void workerNumeric(int threadId, uint64_t start, uint64_t end, 
                   const char* targetHash, int hashType) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = (hashType == 1) ? EVP_md5() : EVP_sha256();
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = (hashType == 1) ? 16 : 32;
    char hexOutput[65];
    char numBuf[32];
    
    uint64_t localCount = 0;
    const uint64_t REPORT_INTERVAL = 10000;
    
    for(uint64_t i = start; i < end && !passwordFound.load(memory_order_relaxed); i++) {
        int len = numToStr(i, numBuf);
        
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, numBuf, len);
        EVP_DigestFinal_ex(ctx, hash, &hashLen);
        
        toHexFast(hash, hashLen, hexOutput);
        
        localCount++;
        
        if(strcmp(hexOutput, targetHash) == 0) {
            passwordFound.store(true, memory_order_relaxed);
            lock_guard<mutex> lock(coutMutex);
            foundPassword = string(numBuf);
            break;
        }
        
        if(localCount % REPORT_INTERVAL == 0) {
            globalAttempts.fetch_add(REPORT_INTERVAL, memory_order_relaxed);
            localCount = 0;
        }
    }
    
    globalAttempts.fetch_add(localCount, memory_order_relaxed);
    EVP_MD_CTX_free(ctx);
}

// Worker for alphanumeric passwords (OPTIMIZED - per length)
void workerAlpha(int threadId, uint64_t start, uint64_t end, int pwdLen,
                 const char* targetHash, int hashType, const char* charset, int charsetLen) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = (hashType == 1) ? EVP_md5() : EVP_sha256();
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = (hashType == 1) ? 16 : 32;
    char hexOutput[65];
    char password[32];
    
    uint64_t localCount = 0;
    const uint64_t REPORT_INTERVAL = 5000;
    
    for(uint64_t i = start; i < end && !passwordFound.load(memory_order_relaxed); i++) {
        indexToPasswordFixed(i, charset, charsetLen, pwdLen, password);
        
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, password, pwdLen);
        EVP_DigestFinal_ex(ctx, hash, &hashLen);
        
        toHexFast(hash, hashLen, hexOutput);
        
        localCount++;
        
        if(strcmp(hexOutput, targetHash) == 0) {
            passwordFound.store(true, memory_order_relaxed);
            lock_guard<mutex> lock(coutMutex);
            foundPassword = string(password);
            break;
        }
        
        if(localCount % REPORT_INTERVAL == 0) {
            globalAttempts.fetch_add(REPORT_INTERVAL, memory_order_relaxed);
            localCount = 0;
        }
    }
    
    globalAttempts.fetch_add(localCount, memory_order_relaxed);
    EVP_MD_CTX_free(ctx);
}

void testPassword(const string& targetHash, int hashType, int mode, uint64_t maxAttempts) {
    cout << CYAN << "\n[*] Starting password cracker..." << RESET << endl;
    cout << YELLOW << "[*] Target Hash: " << targetHash << RESET << endl;
    
    int numThreads = thread::hardware_concurrency();
    if(numThreads == 0) numThreads = 4;
    
    cout << BLUE << "[*] Using " << numThreads << " threads for maximum speed!" << RESET << endl;
    
    passwordFound.store(false);
    globalAttempts.store(0);
    foundPassword = "";
    
    auto start = high_resolution_clock::now();
    vector<thread> threads;
    
    if(mode == 1) {
        // Numeric mode
        cout << GREEN << "[*] Mode: Numeric (0-9)" << RESET << endl;
        cout << YELLOW << "[*] Max attempts: " << maxAttempts << RESET << endl;
        
        uint64_t chunkSize = maxAttempts / numThreads;
        for(int i = 0; i < numThreads; i++) {
            uint64_t threadStart = i * chunkSize;
            uint64_t threadEnd = (i == numThreads - 1) ? maxAttempts : (i + 1) * chunkSize;
            threads.emplace_back(workerNumeric, i, threadStart, threadEnd, 
                               targetHash.c_str(), hashType);
        }
    } else {
        // Alphanumeric mode
        const char* charset;
        int charsetLen;
        
        if(mode == 2) {
            charset = CHARSET_LOWERCASE;
            charsetLen = 26;
            cout << GREEN << "[*] Mode: Lowercase (a-z)" << RESET << endl;
        } else if(mode == 3) {
            charset = CHARSET_ALPHA;
            charsetLen = 52;
            cout << GREEN << "[*] Mode: Alpha (a-z, A-Z)" << RESET << endl;
        } else {
            charset = CHARSET_ALPHANUM;
            charsetLen = 62;
            cout << GREEN << "[*] Mode: Alphanumeric (0-9, a-z, A-Z)" << RESET << endl;
        }
        
        cout << CYAN << "Enter max password length to test (e.g., 4 for 4-char passwords): " << RESET;
        int maxLen;
        cin >> maxLen;
        cin.ignore();
        
        // Process each length separately
        for(int len = 1; len <= maxLen && !passwordFound.load(); len++) {
            uint64_t combos = ipow(charsetLen, len);
            
            cout << YELLOW << "[*] Testing length " << len << " (" << combos << " combinations)" << RESET << endl;
            
            uint64_t chunkSize = combos / numThreads;
            threads.clear();
            
            for(int i = 0; i < numThreads; i++) {
                uint64_t threadStart = i * chunkSize;
                uint64_t threadEnd = (i == numThreads - 1) ? combos : (i + 1) * chunkSize;
                threads.emplace_back(workerAlpha, i, threadStart, threadEnd, len,
                                   targetHash.c_str(), hashType, charset, charsetLen);
            }
            
            for(auto& t : threads) {
                if(t.joinable()) t.join();
            }
            
            if(passwordFound.load()) break;
        }
        
        threads.clear();
    }
    
    // Progress monitor
    thread monitor([&]() {
        uint64_t lastReported = 0;
        while(!passwordFound.load(memory_order_relaxed)) {
            this_thread::sleep_for(milliseconds(500));
            uint64_t current = globalAttempts.load(memory_order_relaxed);
            
            if(current - lastReported >= 50000) {
                auto now = high_resolution_clock::now();
                auto elapsed = duration_cast<milliseconds>(now - start);
                
                if(elapsed.count() > 0) {
                    double speed = current * 1000.0 / elapsed.count();
                    
                    lock_guard<mutex> lock(coutMutex);
                    cout << MAGENTA << "[~] " << current << " tested | " 
                         << CYAN << (uint64_t)speed << " h/s" << RESET << endl;
                    
                    lastReported = current;
                }
            }
        }
    });
    
    if(mode == 1) {
        for(auto& t : threads) {
            if(t.joinable()) t.join();
        }
    }
    
    passwordFound.store(true);
    if(monitor.joinable()) monitor.join();
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);
    
    if(!foundPassword.empty()) {
        cout << GREEN << BOLD << "\n========================================" << RESET << endl;
        cout << GREEN << BOLD << "       PASSWORD FOUND!" << RESET << endl;
        cout << GREEN << BOLD << "========================================" << RESET << endl;
        cout << GREEN << "[+] Password: " << BOLD << foundPassword << RESET << endl;
        cout << YELLOW << "[+] Attempts: " << globalAttempts.load() << RESET << endl;
        cout << YELLOW << "[+] Time: " << duration.count() / 1000.0 << " sec" << RESET << endl;
        if(duration.count() > 0) {
            cout << CYAN << "[+] Speed: " << (uint64_t)(globalAttempts.load() * 1000.0 / duration.count()) 
                 << " h/s" << RESET << endl;
        }
        cout << GREEN << BOLD << "========================================" << RESET << endl;
    } else {
        cout << RED << "\n[-] Password not found" << RESET << endl;
        cout << YELLOW << "[*] Attempts: " << globalAttempts.load() << RESET << endl;
        cout << YELLOW << "[*] Time: " << duration.count() / 1000.0 << " sec" << RESET << endl;
    }
}

string createHash(const string& input, int hashType) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    
    if(hashType == 1) {
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    } else {
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    }
    
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);
    
    char hexOutput[65];
    toHexFast(hash, hashLen, hexOutput);
    return string(hexOutput);
}

void printBanner() {
    cout << CYAN << BOLD << "\n========================================" << RESET << endl;
    cout << CYAN << BOLD << "    ULTRA-FAST HASH CRACKER v1.0.2" << RESET << endl;
    cout << CYAN << BOLD << "========================================" << RESET << endl;
    cout << GREEN << "[+] Multi-threaded & Optimized" << RESET << endl;
    cout << GREEN << "[+] Numeric & Alphanumeric support" << RESET << endl;
    cout << YELLOW << "[!] Educational purposes only!" << RESET << endl;
    cout << MAGENTA << "[!] SPEED BOOST: 3-5x faster!" << RESET << endl;
    cout << CYAN << BOLD << "========================================" << RESET << endl;
}

int main() {
    enableColors();
    printBanner();
    
    while(true) {
        cout << BLUE << BOLD << "\n======= MAIN MENU =======" << RESET << endl;
        cout << WHITE << "1) Create hash then test" << RESET << endl;
        cout << WHITE << "2) Only create a hash" << RESET << endl;
        cout << WHITE << "3) Crack existing hash" << RESET << endl;
        cout << WHITE << "4) Benchmark" << RESET << endl;
        cout << WHITE << "5) Exit" << RESET << endl;
        cout << CYAN << ">> Option: " << RESET;
        
        int option;
        cin >> option;
        cin.ignore();
        
        if(option == 5) {
            cout << GREEN << "\n[*] Exiting... Stay safe!" << RESET << endl;
            break;
        }
        
        if(option == 4) {
            cout << CYAN << "\n[*] Running benchmark..." << RESET << endl;
            
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            char numBuf[32];
            unsigned char hash[16];
            unsigned int hashLen;
            
            auto start = high_resolution_clock::now();
            for(int i = 0; i < 1000000; i++) {
                numToStr(i, numBuf);
                EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
                EVP_DigestUpdate(ctx, numBuf, strlen(numBuf));
                EVP_DigestFinal_ex(ctx, hash, &hashLen);
            }
            auto end = high_resolution_clock::now();
            auto duration = duration_cast<milliseconds>(end - start);
            
            EVP_MD_CTX_free(ctx);
            
            if(duration.count() > 0) {
                cout << GREEN << "[+] Single-thread speed: " 
                     << (uint64_t)(1000000.0 * 1000.0 / duration.count()) 
                     << " h/s" << RESET << endl;
            }
            continue;
        }
        
        if(option == 3) {
            // BEGINNER / ADVANCED for option 3 only
            cout << BLUE << BOLD << "\n======= SELECT MODE =======" << RESET << endl;
            cout << WHITE << "1) Beginner - Just enter hash" << RESET << endl;
            cout << WHITE << "2) Advanced - Hash type + crack mode" << RESET << endl;
            cout << CYAN << ">> Mode: " << RESET;
            
            int userMode;
            cin >> userMode;
            cin.ignore();
            
            if(userMode == 1) {
                // BEGINNER MODE - Auto-detect and simple
                cout << CYAN << "\n>> Enter hash to crack: " << RESET;
                string hash;
                getline(cin, hash);
                
                int hashType = (hash.length() == 32) ? 1 : 2; // Auto-detect: 32=MD5, 64=SHA256
                
                cout << BLUE << BOLD << "\n======= CRACK MODE =======" << RESET << endl;
                cout << WHITE << "1) Numeric only (0-9)" << RESET << endl;
                cout << WHITE << "2) Lowercase (a-z)" << RESET << endl;
                cout << WHITE << "3) Alpha (a-z, A-Z)" << RESET << endl;
                cout << WHITE << "4) Alphanumeric (a-z, A-Z, 0-9)" << RESET << endl;
                cout << CYAN << ">> Mode: " << RESET;
                int mode;
                cin >> mode;
                cin.ignore();
                
                if(mode == 1) {
                    cout << CYAN << ">> Max number to test: " << RESET;
                    uint64_t maxNum;
                    cin >> maxNum;
                    cin.ignore();
                    testPassword(hash, hashType, mode, maxNum);
                } else {
                    testPassword(hash, hashType, mode, 0);
                }
                
            } else if(userMode == 2) {
                // ADVANCED MODE - Full control
                cout << BLUE << BOLD << "\n======= HASH TYPE =======" << RESET << endl;
                cout << WHITE << "1) MD5" << RESET << endl;
                cout << WHITE << "2) SHA256" << RESET << endl;
                cout << CYAN << ">> Type: " << RESET;
                int hashType;
                cin >> hashType;
                cin.ignore();
                
                if(hashType != 1 && hashType != 2) {
                    cout << RED << "[-] Invalid!" << RESET << endl;
                    continue;
                }
                
                cout << CYAN << "\n>> Hash to crack: " << RESET;
                string hash;
                getline(cin, hash);
                
                cout << BLUE << BOLD << "\n======= CRACK MODE =======" << RESET << endl;
                cout << WHITE << "1) Numeric only (0-9)" << RESET << endl;
                cout << WHITE << "2) Lowercase (a-z)" << RESET << endl;
                cout << WHITE << "3) Alpha (a-z, A-Z)" << RESET << endl;
                cout << WHITE << "4) Alphanumeric (a-z, A-Z, 0-9)" << RESET << endl;
                cout << CYAN << ">> Mode: " << RESET;
                int mode;
                cin >> mode;
                cin.ignore();
                
                if(mode == 1) {
                    cout << CYAN << ">> Max attempts: " << RESET;
                    uint64_t maxAttempts;
                    cin >> maxAttempts;
                    cin.ignore();
                    testPassword(hash, hashType, mode, maxAttempts);
                } else {
                    testPassword(hash, hashType, mode, 0);
                }
            } else {
                cout << RED << "[-] Invalid mode!" << RESET << endl;
            }
            
            continue;
        }
        
        cout << BLUE << BOLD << "\n======= HASH TYPE =======" << RESET << endl;
        cout << WHITE << "1) MD5" << RESET << endl;
        cout << WHITE << "2) SHA256" << RESET << endl;
        cout << CYAN << ">> Type: " << RESET;
        int hashType;
        cin >> hashType;
        cin.ignore();
        
        if(hashType != 1 && hashType != 2) {
            cout << RED << "[-] Invalid!" << RESET << endl;
            continue;
        }
        
        if(option == 1 || option == 2) {
            cout << CYAN << "\n>> Text to hash: " << RESET;
            string password;
            getline(cin, password);
            
            string hash = createHash(password, hashType);
            cout << GREEN << "\n[+] Hash: " << YELLOW << hash << RESET << endl;
            
            if(option == 2) continue;
            
            cout << BLUE << BOLD << "\n======= CRACK MODE =======" << RESET << endl;
            cout << WHITE << "1) Numeric only (0-9)" << RESET << endl;
            cout << WHITE << "2) Lowercase (a-z)" << RESET << endl;
            cout << WHITE << "3) Alpha (a-z, A-Z)" << RESET << endl;
            cout << WHITE << "4) Alphanumeric (a-z, A-Z, 0-9)" << RESET << endl;
            cout << CYAN << ">> Mode: " << RESET;
            int mode;
            cin >> mode;
            cin.ignore();
            
            if(mode == 1) {
                cout << CYAN << ">> Max attempts: " << RESET;
                uint64_t maxAttempts;
                cin >> maxAttempts;
                cin.ignore();
                testPassword(hash, hashType, mode, maxAttempts);
            } else {
                testPassword(hash, hashType, mode, 0);
            }
        }
    }

    std::cin.get();
    
    return 0;
}