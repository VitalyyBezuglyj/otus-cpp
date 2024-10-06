#include <fmt/core.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "lib.h"

std::vector<std::string> split_line(std::string line, char delimiter) {
    std::string::size_type pos = 0;
    std::vector<std::string> result;
    std::string token;

    while ((pos = line.find(delimiter)) != std::string::npos) {
        token = line.substr(0, pos);
        line.erase(0, pos + 1);
        if (token.empty()) {
            break;
        }
        result.push_back(token);
    }
    if (!line.empty()) {
        result.push_back(line);
    }
    return result;
}

struct IPAddress {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;

    IPAddress() : a(0), b(0), c(0), d(0) {}
    IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
        : a(a), b(b), c(c), d(d) {}
    explicit IPAddress(std::string ip) {
        auto tokens = split_line(ip, '.');
        if (tokens.size() != 4) {
            throw std::runtime_error(fmt::format("Invalid IP address: {}", ip));
        }
        a = std::stoi(tokens[0]);
        b = std::stoi(tokens[1]);
        c = std::stoi(tokens[2]);
        d = std::stoi(tokens[3]);
    }

    std::string to_string() const {
        return fmt::format("{}.{}.{}.{}", a, b, c, d);
    }

    bool operator<(const IPAddress& other) const {
        if (a != other.a) {
            return a < other.a;
        }
        if (b != other.b) {
            return b < other.b;
        }
        if (c != other.c) {
            return c < other.c;
        }
        return d < other.d;
    }
};

int main(int, char**) {
    std::string buffer;
    std::vector<std::tuple<IPAddress, std::string, std::string> > lines_buff;

    while (getline(std::cin, buffer)) {
        if (buffer.empty()) {
            break;
        }

        auto tokens = split_line(buffer, '\t');
        if (tokens.size() != 3) {
            throw std::invalid_argument(fmt::format(
                "Invalid line: {}. Line must contain exactly 3 fields, "
                "separated by tabs. Got: {}",
                buffer, tokens.size()));
        }
        auto new_entry =
            std::make_tuple(IPAddress(tokens[0]), tokens[1], tokens[2]);
        lines_buff.push_back(new_entry);
    }

    auto cmp =
        [](const std::tuple<IPAddress, std::string, std::string>& left,
           const std::tuple<IPAddress, std::string, std::string>& right) {
            return std::get<0>(right) < std::get<0>(left);  // Reverse order
        };
    std::sort(lines_buff.begin(), lines_buff.end(), cmp);

    for (const auto& it : lines_buff) {
        std::cout << fmt::format("{}\n", std::get<0>(it).to_string());
    }

    for (const auto& it : lines_buff) {
        if (std::get<0>(it).a == 1) {
            std::cout << fmt::format("{}\n", std::get<0>(it).to_string());
        }
    }
    for (const auto& it : lines_buff) {
        if (std::get<0>(it).a == 46 && std::get<0>(it).b == 70) {
            std::cout << fmt::format("{}\n", std::get<0>(it).to_string());
        }
    }
    for (const auto& it : lines_buff) {
        if (std::get<0>(it).a == 46 || std::get<0>(it).b == 46 ||
            std::get<0>(it).c == 46 || std::get<0>(it).d == 46) {
            std::cout << fmt::format("{}\n", std::get<0>(it).to_string());
        }
    }
    return 0;
}
