// SuperManager's small ovpncli adapter. Upstream's -a means auto-session,
// not an authentication file; do not put a VPN password/token in argv.
#pragma once

#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

static void supermanager_read_auth_file(const char *path,
                                       std::string &username,
                                       std::string &password)
{
    constexpr size_t maximum = 1024 * 1024;
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        throw std::runtime_error("cannot open --auth-user-pass file");
    struct Close
    {
        int fd;
        ~Close() { close(fd); }
    } close_file{fd};
    struct stat metadata;
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != geteuid() || (metadata.st_mode & 0077) != 0)
        throw std::runtime_error("--auth-user-pass requires a private regular file owned by this user");
    if (metadata.st_size <= 0 || metadata.st_size > static_cast<off_t>(maximum))
        throw std::runtime_error("--auth-user-pass file must be between 1 byte and 1 MiB");

    std::string body;
    struct Wipe
    {
        std::string &body;
        ~Wipe()
        {
            // Keep the temporary copy out of allocator reuse after parsing.
            volatile char *p = body.data();
            for (size_t i = 0; i < body.size(); ++i)
                p[i] = 0;
        }
    } wipe{body};
    char chunk[4096] = {};
    struct WipeChunk
    {
        char (&bytes)[4096];
        ~WipeChunk()
        {
            // Also erase the last read if validation/allocation throws.
            volatile char *p = bytes;
            for (size_t i = 0; i < sizeof(bytes); ++i)
                p[i] = 0;
        }
    } wipe_chunk{chunk};
    for (;;)
    {
        const ssize_t count = read(fd, chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            throw std::runtime_error("cannot read --auth-user-pass file");
        if (count == 0)
            break;
        if (body.size() + static_cast<size_t>(count) > maximum)
            throw std::runtime_error("--auth-user-pass file exceeds 1 MiB");
        body.append(chunk, static_cast<size_t>(count));
        volatile char *p = chunk;
        for (size_t i = 0; i < sizeof(chunk); ++i)
            p[i] = 0;
    }
    // The helper writes username LF password LF. Accept an omitted final LF
    // for manually-created files; no other delimiters or control bytes.
    if (!body.empty() && body.back() == '\n')
        body.pop_back();
    const size_t separator = body.find('\n');
    if (separator == std::string::npos || separator == 0 || separator + 1 == body.size())
        throw std::runtime_error("--auth-user-pass requires two nonempty lines");
    for (size_t i = 0; i < body.size(); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(body[i]);
        if (i != separator && (c < 32 || c == 127))
            throw std::runtime_error("--auth-user-pass contains an extra line or control byte");
    }
    username.assign(body, 0, separator);
    password.assign(body, separator + 1, std::string::npos);
}
