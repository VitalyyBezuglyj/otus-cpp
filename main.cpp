#include <iostream>
#include <string>
#include <vector>

#include "lib.h"

void greet() {
    std::cout << "Hello World!" << std::endl;
    std::cout << "IP filter tool" << std::endl;
    std::cout << "Version: " << version() << std::endl;
}

int main(int, char**) {
    greet();

    std::string buffer;
    std::vector<std::string> lines_buff;

    while (getline(std::cin, buffer)) {
        if (buffer.empty()) {
            break;
        }
        lines_buff.push_back(buffer);
    }

    std::cout << "You entered the following lines: " << std::endl;
    for (const auto& it : lines_buff) {
        std::cout << it << std::endl;
    }
    return 0;
}
