#include <cstdint>
#include <array>
#include <iostream>
#include <string>
#include <bitset>
#include <iomanip>
#include <sstream>
#include "DES.hpp"

void gen_round_keys(const uint64_t& KEY, std::array<uint64_t, 16>& K);
void permute(const uint64_t& CONTENT, uint64_t& M);
void iterate(const std::array<uint64_t, 16>& K, uint64_t& M, int method);
uint32_t f(const uint32_t& R, const uint64_t& K);

int main(int argc, char** argv) {
    std::cout << "To decrypt, enter 0. To encrypt, enter 1." << std::endl;
    int method; std::cin >> method;
    if (method != 0 && method != 1) {
        return 1;
    };

    std::cout << "For a binary key, enter 0. For a plaintext key, enter 1." << std::endl;
    int keyType; std::cin >> keyType;
    if (keyType != 0 && keyType != 1) {
        return 1;
    };

    std::cout << "Enter the key." << std::endl;
    uint64_t KEY;
    if (keyType) {
        KEY = 0;
        std::string plaintext;
        std::cin >> plaintext;
        for (const auto& c : plaintext) {
            KEY <<= 8;
            KEY |= c;
        }

    } else {
        std::string binary;
        std::cin >> binary;
        KEY = std::bitset<64>(std::string(64 - binary.size(), '0') + binary).to_ullong();
    }

    uint64_t CONTENT;
    if (method) {
        std::cout << "For a binary message, enter 0. For a plaintext message, enter 1." << std::endl;
        int mType; std::cin >> mType;
        if (mType != 0 && mType != 1) {
            return 1;
        };

        std::cout << "Enter the message." << std::endl;
        if (mType) {
            CONTENT = 0;
            std::string plaintext;
            std::cin >> plaintext;
            for (const auto& c : plaintext) {
                CONTENT <<= 8;
                CONTENT |= c;
            }

        } else {
            std::string binary;
            std::cin >> binary;
            CONTENT = std::bitset<64>(std::string(64 - binary.size(), '0') + binary).to_ullong();
        }

    } else {
        std::cout << "For a binary cipher, enter 0. For a plaintext cipher, enter 1." << std::endl;
        int mType; std::cin >> mType;
        if (mType != 0 && mType != 1) {
            return 1;
        };

        std::cout << "Enter the cipher." << std::endl;
        if (mType) {
            CONTENT = 0;
            std::string plaintext;
            std::cin >> plaintext;
            for (const auto& c : plaintext) {
                CONTENT <<= 8;
                CONTENT |= c;
            }
            
        } else {
            std::string binary;
            std::cin >> binary;
            CONTENT = std::bitset<64>(std::string(64 - binary.size(), '0') + binary).to_ullong();
        }
    }

    /* Reverse the input binary key */
    uint64_t revKey = 0;
    for (int i = 0; i < 64; ++i) {
        if (KEY & (1ULL << i)) {
            revKey |= (1ULL << (63 - i));
        }
    }
    KEY = revKey;

    /* Reverse the input binary content */
    uint64_t revContent = 0;
    for (int i = 0; i < 64; ++i) {
        if (CONTENT & (1ULL << i)) {
            revContent |= (1ULL << (63 - i));
        }
    }
    CONTENT = revContent;

    /* Generate the 16 round keys */
    std::array<uint64_t, 16> K;
    gen_round_keys(KEY, K);

    /* Perform the initial permutation function */
    uint64_t M;
    permute(CONTENT, M);

    /* Perform 16 iterations */
    iterate(K, M, method);

    /* Reverse the output binary */
    uint64_t revM = 0;
    for (int i = 0; i < 64; ++i) {
        if (M & (1ULL << i)) {
            revM |= (1ULL << (63 - i));
        }
    }
    M = revM;

    /* Print output */
    std::cout << "\nDecimal:" << std::endl;
    std::cout << M << std::endl;

    std::cout << "\nBinary:" << std::endl;
    std::cout << std::bitset<64>(M).to_string() << std::endl;

    std::cout << "\nHex:" << std::endl;
    {
        std::ostringstream oss;
        oss << std::hex << std::setw(16) << std::setfill('0') << M;
        std::cout << oss.str() << std::endl;
    }

    std::cout << "\nPlaintext:" << std::endl;
    for (int i = 7; i > -1; --i) {
        char c = static_cast<char>(M >> (i * 8));
        std::cout << c;
    }
    std::cout << std::endl;

    return 0;
}

void gen_round_keys(const uint64_t& KEY, std::array<uint64_t, 16>& K) {
    /* Generate C0 */
    std::array<uint32_t, 17> C;
    C.at(0) = 0;
    for (int i = 0; i < 28; ++i) {
        C.at(0) |= ((KEY >> (PC1.at(i) - 1)) & 1) << i;
    }

    /* Generate D0 */
    std::array<uint32_t, 17> D;
    D.at(0) = 0;
    for (int i = 28; i < 56; ++i) {
        D.at(0) |= ((KEY >> (PC1.at(i) - 1)) & 1) << (i - 28);
    }

    /* Generate subkeys */
    for (int i = 1; i < 17; ++i) {
        C.at(i) = (C.at(i - 1) >> 1) | ((C.at(i - 1) & 1) << 27);
        D.at(i) = (D.at(i - 1) >> 1) | ((D.at(i - 1) & 1) << 27);
        if (LSS.at(i - 1)) {
            C.at(i) = (C.at(i) >> 1) | ((C.at(i) & 1) << 27);
            D.at(i) = (D.at(i) >> 1) | ((D.at(i) & 1) << 27);
        }

        K.at(i - 1) = 0;
        for (int j = 0; j < 48; ++j) {
            if (PC2.at(j) <= 28) {
                K.at(i - 1) |= (static_cast<uint64_t>(C.at(i) >> (PC2.at(j) - 1)) & 1) << j;
            } else {
                K.at(i - 1) |= (static_cast<uint64_t>(D.at(i) >> (PC2.at(j) - 29)) & 1) << j;
            }
        }
        std::cout << 'K' << i << ": " << std::bitset<64>(K.at(i - 1)).to_string() << std::endl;
    }
}

void permute(const uint64_t& CONTENT, uint64_t& M) {
    M = 0;
    for (int i = 0; i < 64; ++i) {
        M |= ((CONTENT >> (IP.at(i) - 1)) & 1) << i;
    }
}

void iterate(const std::array<uint64_t, 16>& K, uint64_t& M, int method) {
    std::array<uint32_t, 17> L, R;
    L.at(0) = static_cast<uint32_t>(M);
    R.at(0) = static_cast<uint32_t>(M >> 32);

    std::cout << "\nL0: " << L.at(0) << std::endl;

    for (int i = 1; i < 17; ++i) {
        L.at(i) = R.at(i - 1);
        
        uint32_t _f;
        if (method) {
            // Encrypt
            _f = f(R.at(i - 1), K.at(i - 1));
        } else {
            // Decrypt
            _f = f(R.at(i - 1), K.at(16 - i));
        }
        std::cout << "f(R" << i-1 << ", K" << i << "): " << std::bitset<32>(_f).to_string() << std::endl;
        R.at(i) = L.at(i - 1) ^ _f;
        std::cout << 'L' << i << ": " << L.at(i) << std::endl;
        std::cout << 'R' << i << ": " << R.at(i) << std::endl;
    }

    uint64_t RL = R.at(16) | (static_cast<uint64_t>(L.at(16)) << 32);
    M = 0;
    for (int i = 0; i < 64; ++i) {
        M |= ((RL >> (IIP.at(i) - 1)) & 1) << i;
    }
}

uint32_t f(const uint32_t& R, const uint64_t& K) {
    uint64_t _R = 0;
    for (int i = 0; i < 48; ++i) {
        _R |= static_cast<uint64_t>((R >> (E.at(i) - 1)) & 1) << i;
    }
    _R ^= K;

    uint32_t L = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t row, col;
        row = (((_R >> (i * 6)) << 1) & 2) | ((_R >> (i * 6 + 5)) & 1);
        col = ((_R >> (i * 6 + 1) & 1) << 3) | ((_R >> (i * 6 + 1) & 2) << 1) | ((_R >> (i * 6 + 1) & 4) >> 1) | ((_R >> (i * 6 + 1) & 8) >> 3);
        uint32_t _S = S.at(i).at(row).at(col);
        L |= (((_S & 1) << 3) | ((_S & 2) << 1) | ((_S & 4) >> 1) | (_S >> 3)) << (i * 4);
    }

    uint32_t _P = 0;
    for (int i = 0; i < 32; ++i) {
        _P |= ((L >> (P.at(i) - 1)) & 1) << i;
    }

    return _P;
}

//uint64_t KEY = 0b0100110001001111010101100100010101000011010100110100111001000100;
//uint64_t CONTENT = 0b1100101011101101101000100110010101011111101101110011100001110011;