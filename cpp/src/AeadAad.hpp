#pragma once

#include <vector>

namespace floe {

class AeadAad {
public:
    static AeadAad nonTerminal(uint64_t segmentCounter);
    static AeadAad terminal(uint64_t segmentCounter);
    
    [[nodiscard]] const std::vector<uint8_t>& getBytes() const;

private:
    AeadAad(uint64_t segmentCounter, uint8_t terminalityByte);
    std::vector<uint8_t> bytes_;
};

}
