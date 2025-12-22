#pragma once

#include <cstdint>
#include <string>

namespace floe {

enum class HashType : uint8_t {
    SHA384 = 0
};

class Hash {
public:
    [[nodiscard]] static const Hash& fromType(HashType type);
    
    [[nodiscard]] HashType getType() const { return type_; }
    [[nodiscard]] uint8_t getId() const { return static_cast<uint8_t>(type_); }
    [[nodiscard]] const std::string& getOsslHmacName() const { return osslHmacName_; }
    [[nodiscard]] int getLength() const { return length_; }

private:
    Hash(HashType type, std::string osslHmacName, int length);
    
    HashType type_;
    std::string osslHmacName_;
    int length_;
};

}
