#include <gtest/gtest.h>

#include "lib/lib.h"

// Test case
TEST(CheckVersion, VersionGTZero) { EXPECT_GT(version(), 0); }

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
