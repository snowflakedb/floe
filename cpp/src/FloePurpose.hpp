#pragma once

#include <vector>
#include <string_view>

namespace floe {

class FloePurpose {
public:
    virtual ~FloePurpose() = default;
    [[nodiscard]] virtual std::vector<uint8_t> generate() const = 0;
};

class HeaderTagFloePurpose : public FloePurpose {
public:
    static const HeaderTagFloePurpose& getInstance();
    [[nodiscard]] std::vector<uint8_t> generate() const override;

private:
    HeaderTagFloePurpose() = default;
    static constexpr std::string_view PREFIX = "HEADER_TAG:";
};

class DekTagFloePurpose : public FloePurpose {
public:
    explicit DekTagFloePurpose(uint64_t segmentCount);
    [[nodiscard]] std::vector<uint8_t> generate() const override;

private:
    std::vector<uint8_t> bytes_;
    static constexpr std::string_view PREFIX = "DEK:";
};

class MessageKeyPurpose : public FloePurpose {
public:
    static const MessageKeyPurpose& getInstance();
    [[nodiscard]] std::vector<uint8_t> generate() const override;

private:
    MessageKeyPurpose() = default;
    static constexpr std::string_view PREFIX = "MESSAGE_KEY:";
};

}
