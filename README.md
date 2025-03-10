# HashKit

HashKit is a C library for cryptographic hashing algorithms. It provides implementations for various hashing algorithms such as SHA-2 and MD5.
## Features
- **SHA-1**: Secure Hash Algorithm 1 implementation.
- **SHA-2**: Secure Hash Algorithm 2 implementation.
- **MD5**: Message-Digest Algorithm 5 implementation

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/MKKHLIF/HashKit.git
   cd HashKit
    ```
2. Build the library:
   ```bash
    mkdir build
    cd build
    cmake ..
    make
   ```
## Usage

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sha2.h"

void compare_bytes(const uint8_t* expected, const uint8_t* actual, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (expected[i] != actual[i]) {
            printf("Mismatch at byte %zu\n", i);
            return;
        }
    }
    printf("Hashes match!\n");
}

int main() {
    const char* input = "The quick brown fox jumps over the lazy dog";
    uint8_t sha224_digest[28];
    uint8_t sha256_digest[32];
    uint8_t sha384_digest[48];
    uint8_t sha512_digest[64];
    
    sha224_hash((uint8_t*)input, strlen(input), sha224_digest);
    sha256_hash((uint8_t*)input, strlen(input), sha256_digest);
    sha384_hash((uint8_t*)input, strlen(input), sha384_digest);
    sha512_hash((uint8_t*)input, strlen(input), sha512_digest);
    
    printf("SHA-224: ");
    for (size_t i = 0; i < sizeof(sha224_digest); i++) printf("%02x", sha224_digest[i]);
    printf("\n");
    
    printf("SHA-256: ");
    for (size_t i = 0; i < sizeof(sha256_digest); i++) printf("%02x", sha256_digest[i]);
    printf("\n");
    
    printf("SHA-384: ");
    for (size_t i = 0; i < sizeof(sha384_digest); i++) printf("%02x", sha384_digest[i]);
    printf("\n");
    
    printf("SHA-512: ");
    for (size_t i = 0; i < sizeof(sha512_digest); i++) printf("%02x", sha512_digest[i]);
    printf("\n");
    
    return 0;
}
```

## License
Licensed under the [MIT license](LICENSE.md).