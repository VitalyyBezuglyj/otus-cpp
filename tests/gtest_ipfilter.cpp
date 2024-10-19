#include <gtest/gtest.h>
#include <openssl/evp.h>  // For SHA-3 hashing
#include <openssl/sha.h>  // SHA-3 functions

#include <algorithm>  // for std::transform
#include <fstream>
#include <sstream>
#include <string>

#include "ipfilter/ipfilter.h"

const std::string TEST_DATA_PATH = "tests/data/ip_filter.tsv";
const std::string SOLUTION_HASH_STR =
    "9c14006ec1c4b0210308e5da2a24a71ea0ff09c87f96dba122b16e47becccdcf";

const std::string expected_sha3_hash =
    "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722";

std::string calculateSHA3_256(const std::stringstream& ss) {
    std::string data = ss.str();

    // Create a buffer to hold the SHA3-256 result (32 bytes for SHA3-256)
    unsigned char digest[SHA256_DIGEST_LENGTH];

    // Compute SHA3-256 hash
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(context, data.c_str(), data.size());
    EVP_DigestFinal_ex(context, digest, NULL);
    EVP_MD_CTX_free(context);

    // Convert digest to a hex string
    std::stringstream sha3string;
    sha3string << std::hex;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sha3string << std::setw(2) << std::setfill('0')
                   << static_cast<int>(digest[i]);
    }

    return sha3string.str();  // Return the SHA3-256 hex string
}

TEST(CheckFilter, FilterPassesGivenTestCase) {
    std::ifstream file(TEST_DATA_PATH);

    if (!file) {
        FAIL() << "Failed to open file: " << TEST_DATA_PATH;
    }

    std::stringstream buffer_out;

    // Call the filter function
    ipfilter(file, buffer_out);
    file.close();

    auto answer_hash_str = calculateSHA3_256(buffer_out);

    EXPECT_EQ(SOLUTION_HASH_STR, answer_hash_str);
}
