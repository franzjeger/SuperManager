// SuperManager's local ovpncli adapter. No credentials in argv or environment.
#pragma once
#include <cerrno>
#include <chrono>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

inline std::string supermanager_password_stdin()
{
    constexpr size_t limit = 65536;
    std::string value;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (true) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw std::runtime_error("Credential input timed out");
        pollfd descriptor{STDIN_FILENO, POLLIN, 0};
        const auto ready = ::poll(&descriptor, 1, static_cast<int>(remaining));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) throw std::runtime_error("Credential input unavailable");
        char buffer[4096];
        const auto count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("Credential input failed");
        if (count == 0) break;
        if (value.size() + static_cast<size_t>(count) > limit)
            throw std::runtime_error("Credential input exceeds size limit");
        for (ssize_t i = 0; i < count; ++i) {
            const auto c = static_cast<unsigned char>(buffer[i]);
            if (c < 32 || c == 127) throw std::runtime_error("Credential contains control characters");
        }
        value.append(buffer, static_cast<size_t>(count));
        volatile char *wipe = buffer;
        for (size_t i = 0; i < sizeof(buffer); ++i) wipe[i] = 0;
    }
    if (value.empty()) throw std::runtime_error("Credential input is empty");
    return value;
}
