#include <utility>

#include "floe/Hash.hpp"
#include "floe/FloeException.hpp"

namespace floe {

Hash::Hash(const HashType type, std::string osslHmacName, const int length)
    : type_(type),
      osslHmacName_(std::move(osslHmacName)),
      length_(length) { }

const Hash& Hash::fromType(const HashType type) {
    switch (type) {
        case HashType::SHA384: {
            static const Hash instance(type, "SHA384", 48);
            return instance;
        }
        default:
            throw FloeException("Unknown hash type");
    }
}

}
