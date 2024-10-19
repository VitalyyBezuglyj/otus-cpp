#include <gtest/gtest.h>
#include <openssl/evp.h>  // For SHA-3 hashing
#include <openssl/sha.h>  // SHA-3 functions

#include <algorithm>  // for std::transform
#include <fstream>
#include <sstream>
#include <string>

#include "ipfilter/ipfilter.h"

const std::string TEST_DATA_PATH = "data/ip_filter.tsv";
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
    sha3string << std::hex << std::uppercase;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sha3string << std::setw(2) << std::setfill('0')
                   << static_cast<int>(digest[i]);
    }

    return sha3string.str();  // Return the SHA3-256 hex string
}

std::string toLowercase(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

TEST(SHA3Test, CompareSHA3Hash) {
    // Setup: Create a stringstream with the contents to hash
    std::stringstream ss;
    ss << "Hello, world!";

    // Calculate the SHA3-256 hash
    std::string calculated_hash = toLowercase(calculateSHA3_256(ss));

    // Compare the calculated hash with the expected (ground truth) hash
    EXPECT_EQ(calculated_hash, expected_sha3_hash);
}

TEST(CheckFilter, FilterPassesGivenTestCase) {
    std::ifstream file(TEST_DATA_PATH);

    if (!file) {
        std::cerr << "Unable to open file!" << std::endl;
    }

    std::stringstream buffer_in;
    std::stringstream buffer_out;

    buffer_in << file.rdbuf();
    file.close();

    // Call the filter function
    ipfilter(buffer_in, buffer_out);

    std::string buffer_out_str = buffer_out.str();
    std::cout << buffer_out_str;

    auto answer_hash_str = toLowercase(calculateSHA3_256(buffer_out));

    EXPECT_EQ(SOLUTION_HASH_STR, answer_hash_str);
}
