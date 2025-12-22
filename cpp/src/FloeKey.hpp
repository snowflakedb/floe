#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace floe {

class FloeKey {
public:
    explicit FloeKey(std::span<const uint8_t> keyData);
    ~FloeKey();
    
    FloeKey(const FloeKey&) = delete;
    FloeKey& operator=(const FloeKey&) = delete;
    FloeKey(FloeKey&&) noexcept = default;
    FloeKey& operator=(FloeKey&&) noexcept = default;
    
    [[nodiscard]] const std::vector<uint8_t>& getKeyData() const;

private:
    std::vector<uint8_t> keyData_;
};

}
