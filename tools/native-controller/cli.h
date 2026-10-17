#pragma once
#include "platform.h"
#include "relay_storage.h"

// Command-line operations that need no window. Arguments are UTF-8; args[0] is
// the command (for example "--status"). selectedSerial is "" or a validated serial.
int runCli(const std::vector<std::string> &args, const std::string &selectedSerial);
bool isGuiCommand(const std::vector<std::string> &args);
// UTF-8 arguments without argv[0] (Windows reads the Unicode command line).
std::vector<std::string> commandLine(int argc, char **argv);
// Removes "--device SERIAL" from args; false on a repeated/missing/invalid serial.
bool splitDevice(std::vector<std::string> &args, std::string &serial);
uint16_t parsePort(const std::string &number); // 1-65535 or throws

// Reads a secret from the controlling terminal with echo disabled. Never from
// argv, environment, redirected stdin or command output.
struct ConsolePassword {
    std::wstring value;
    ~ConsolePassword() { wipe(value); }
    void read(bool confirm, const wchar_t *prompt = nullptr);
    void readCode(); // cloud vault recovery code, normalized
    void newCode();  // generate, print once, require it typed back
};
relay::Vault &openStorage(relay::Storage &storage);
