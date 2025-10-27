# K3Y

> K3Y - a minimal, mysterious and performant local hash testing tool.
> Designed for offline, educational and ethical use only.

---

## Table of contents

* About
* Features
* Requirements
* Build instructions
* Quick start
* Usage examples
* Troubleshooting
* Security and ethics
* License and contribution

---

## About

K3Y is a multi-threaded, optimized command-line utility for generating and testing MD5 and SHA256 hashes. It is intended as an educational tool and for legitimate local testing of passwords and hash-based workflows. K3Y is written in modern C++ (C++17) and relies on OpenSSL for cryptographic primitives.

This project is provided "as is" for learning and authorized testing. Do not use it to access systems, accounts or data without explicit permission.

---

## Features

* Multi-threaded cracking and hashing (uses all available CPU cores)
* MD5 and SHA256 support via OpenSSL
* Numeric and alphanumeric cracking modes
* Per-length optimized enumeration for alphanumeric modes
* Fast hex conversion routines with minimal allocations
* Simple terminal UI with ANSI color support (if terminal supports it)
* Built-in benchmark mode to measure hashing throughput

---

## Requirements

* C++ compiler with C++17 support (g++ or clang++)
* OpenSSL development libraries (libcrypto)
* POSIX threads (pthread) on Unix-like systems
* On Windows: MinGW-w64 or MSYS2 toolchain (or Visual Studio with matching OpenSSL)

Recommended packages:

* Debian / Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

* Arch / Manjaro:

```bash
sudo pacman -S base-devel openssl
```

* macOS (Homebrew):

```bash
brew install openssl
```

* Windows (MSYS2):

Follow MSYS2 installation and install mingw-w64-gcc and mingw-w64-openssl via pacman.

---

## Build instructions

* Windows (MinGW / MSYS2):

```bash
g++ -std=c++17 -O2 K3Y.cpp -o K3Y.exe -lcrypto -lpthread
```

* Linux:

```bash
g++ -std=c++17 -O2 K3Y.cpp -o K3Y -lcrypto -lpthread
```

* macOS (Homebrew OpenSSL):

If `pkg-config` is configured for OpenSSL:

```bash
g++ -std=c++17 -O2 K3Y.cpp -o K3Y $(pkg-config --cflags --libs openssl) -lpthread
```

If `pkg-config` is not available, supply Homebrew paths (adjust prefix if needed):

```bash
g++ -std=c++17 -O2 K3Y.cpp -o K3Y -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lcrypto -lpthread
```

Notes:

* The sample compile commands link `-lcrypto` and `-lpthread`. If your toolchain complains, ensure OpenSSL dev libs are installed and visible to the compiler/linker.
* Do not compile with `-mwindows` on Windows if you want a console application that accepts standard input and prints to the terminal. `-mwindows` makes a GUI subsystem executable and disconnects the standard console streams.

---

## Quick start

* Build using the commands above.

* Run the binary from a terminal:

* Windows:

```powershell
.\K3Y.exe
```

* Linux / macOS:

```bash
./K3Y
```

* Follow the interactive menu to create hashes, run benchmarks, or attempt cracking in numeric or alphanumeric modes.

---

## Usage examples

* Create a hash and test immediately:

1. Start K3Y
2. Choose option 1 (Create hash then test)
3. Select hash type (1 = MD5, 2 = SHA256)
4. Enter the text to hash
5. Choose a cracking mode and options

* Crack an existing hash (beginner mode):

1. Start K3Y
2. Choose option 3 (Crack existing hash)
3. Select Beginner mode and paste the target hash
4. Pick cracking mode (numeric / lowercase / alpha / alphanumeric)
5. Provide max attempts / max length where requested

* Run benchmark:

1. Start K3Y
2. Choose option 4
3. See single-thread hashing throughput reported

---

## Troubleshooting

* Terminal closes immediately after double-clicking the executable on Windows:

  * If the program finishes, Windows will close the console window. Start `K3Y.exe` from an existing terminal (cmd.exe or PowerShell) to view output, or add an input wait at the end of `main` for interactive debugging.
  * If you compiled with `-mwindows`, the binary runs without a console. Rebuild without `-mwindows` for console behavior.

* `std::cin.get()` returns immediately instead of waiting:

  * This commonly happens because a previous `cin >>` left a newline in the input buffer. Use `cin.ignore(numeric_limits<streamsize>::max(), '\n');` before `cin.get()` to flush the leftover newline.

* Linker errors about `-lcrypto`:

  * Ensure OpenSSL development libraries are installed and the include/lib paths are visible to the compiler. On macOS, point the compiler to Homebrew OpenSSL include and lib folders.

* Color output looks garbled on Windows:

  * Enable ANSI escape codes in the terminal (the code toggles ENABLE_VIRTUAL_TERMINAL_PROCESSING). Use a modern Windows Terminal, PowerShell, or enable VT support in CMD.

---

## Security and ethics

* K3Y is provided for education, research and authorized testing only.
* Do not use K3Y to attack systems, accounts or data that you do not own or do not have explicit permission to test.
* Unauthorized use of brute-force or cracking tools is illegal in many jurisdictions and may lead to civil or criminal penalties.
* If you use this tool on systems within a controlled environment, get written authorization and follow the responsible disclosure process.

If you plan to distribute a binary for legitimate testing in an organization, consider code signing and clear documentation for auditors.

---

## License

MIT Licens

---

# Ethicaly

Stay ethical and keep learning. If you want a polished LICENSE file, an ASCII logo, or a README variant for GitHub with badges, tell me which and I will add it.