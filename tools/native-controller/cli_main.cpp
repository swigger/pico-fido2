#include "cli.h"
#include <cstdio>
#include <exception>

int main(int argc, char **argv) {
    try {
        auto args = commandLine(argc, argv); std::string serial;
        if (!splitDevice(args, serial)) throw std::runtime_error("--device requires one 16-digit hexadecimal serial");
        if (isGuiCommand(args)) throw std::runtime_error("This command needs the desktop controller (Esp32KeyConfirm)");
        return runCli(args, serial);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    }
}
