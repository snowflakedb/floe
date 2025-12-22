#pragma once

#include <vector>

namespace floe {

class MessageKey {
public:
    explicit MessageKey(const std::vector<uint8_t>& keyData);
    ~MessageKey();
    
    MessageKey(const MessageKey&) = delete;
    MessageKey& operator=(const MessageKey&) = delete;
    MessageKey(MessageKey&&) noexcept = default;
    MessageKey& operator=(MessageKey&&) noexcept = default;
    
    [[nodiscard]] const std::vector<uint8_t>& getKeyData() const;

private:
    std::vector<uint8_t> keyData_;
};

}
