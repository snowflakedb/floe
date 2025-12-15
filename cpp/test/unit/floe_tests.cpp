#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_all.hpp>
#include "floe.hpp"
#include "../common/CatchExtensions.hpp"

TEST_CASE("OpenSSL SHA-256 is available and working") {
    INFO("Running OpenSSL SHA-256 test suite");
    
    SECTION("empty string") {
        INFO("Testing SHA-256 hash of empty string");
        std::string result = floe::sha256("");
        CHECK_MESSAGE(result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256 incorrectly calculated");
    }

    SECTION("simple string") {
        INFO("Testing SHA-256 hash of 'hello'");
        std::string result = floe::sha256("hello");
        CHECK_MESSAGE(result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "SHA256 incorrectly calculated");
    }

    SECTION("verify hash is not empty") {
        INFO("Testing SHA-256 hash properties");
        std::string result = floe::sha256("test");
        CHECK_FALSE(result.empty());
        CHECK(result.length() == 64);
    }
}
