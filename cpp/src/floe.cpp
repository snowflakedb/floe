#include "floe.hpp"
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

namespace floe {
    std::string sha256(const std::string& input) {
        EVP_MD_CTX* context = EVP_MD_CTX_new();
        if (context == nullptr) {
            return "";
        }

        if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(context);
            return "";
        }

        if (EVP_DigestUpdate(context, input.c_str(), input.length()) != 1) {
            EVP_MD_CTX_free(context);
            return "";
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int lengthOfHash = 0;

        if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
            EVP_MD_CTX_free(context);
            return "";
        }

        EVP_MD_CTX_free(context);

        std::stringstream ss;
        for (unsigned int i = 0; i < lengthOfHash; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return ss.str();
    }
}
