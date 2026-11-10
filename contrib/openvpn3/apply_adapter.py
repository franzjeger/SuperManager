#!/usr/bin/env python3
"""Apply the reviewed credential adapter; fail closed if upstream drifts."""
import pathlib
import shutil
import sys

source = pathlib.Path(sys.argv[1])
adapter = pathlib.Path(__file__).resolve().parent
cli = source / "test/ovpncli/cli.cpp"
text = cli.read_text()


def replace(before, after):
    global text
    if text.count(before) != 1:
        raise SystemExit(f"OpenVPN source differs at adapter anchor: {before[:70]!r}")
    text = text.replace(before, after)


replace("#include <stdlib.h>", '#include <stdlib.h>\n#include "auth_user_pass.hpp"')
replace(
    '        {.name = "username",',
    '        {.name = "auth-user-pass",            .has_arg = required_argument, .flag = nullptr, .val = 7  },\n'
    '        {.name = "username",',
)
replace(
    '        {.name = "auto-sess",                 .has_arg = no_argument,       .flag = nullptr, .val = \'a\'},',
    '        {.name = "auto-sess",                 .has_arg = no_argument,       .flag = nullptr, .val = 8  },',
)
replace('"6:ABCD:F:G:I:K:LM:P:QR:S:TU:W:X:YZ:ac:degh:o:O:b:jk:lmp:q:r:s:t:u:vwxz:"',
        '"6:ABCD:F:G:I:K:LM:P:QR:S:TU:W:X:YZ:a:c:degh:o:O:b:jk:lmp:q:r:s:t:u:vwxz:"')
replace(
    "                case 'u':\n                    username = optarg;",
    "                case 7: // --auth-user-pass\n"
    "                case 'a': // compatibility with SuperManager 1.8.25's -a FILE\n"
    "                    supermanager_read_auth_file(optarg, username, password);\n"
    "                    break;\n"
    "                case 'u':\n                    username = optarg;",
)
replace("                case 'a':\n                    autologinSessions = true;",
        "                case 8: // --auto-sess remains an upstream no-argument option\n                    autologinSessions = true;")
replace("                case 'p':\n                    password = optarg;\n                    break;",
        "                case 'p':\n                    throw std::runtime_error(\"password argv is disabled; use --auth-user-pass FILE\");")
replace('std::cout << "OpenVPN cli 1.0\\n";',
        'std::cout << "SuperManager OpenVPN3 runtime auth-file-v1\\n";')
replace('std::cout << "--password, -p        : password\\n";',
        'std::cout << "--auth-user-pass FILE : private two-line username/password file\\n";')
replace('std::cout << "--auto-sess, -a            : request autologin session\\n";',
        'std::cout << "--auto-sess                : request autologin session\\n";\n'
        '        std::cout << "-a FILE                    : compatibility alias for --auth-user-pass\\n";')
replace(
    "        ret = openvpn_client(argc, argv, nullptr);",
    "        // Static OpenSSL must never read config or providers from Homebrew\n"
    "        // (a user-writable prefix), including inherited environment overrides.\n"
    "        if (setenv(\"OPENSSL_CONF\", \"/dev/null\", 1) != 0\n"
    "            || setenv(\"OPENSSL_MODULES\", \"/var/empty\", 1) != 0\n"
    "            || !OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr))\n"
    "            throw std::runtime_error(\"cannot initialize managed OpenSSL\");\n"
    "        ret = openvpn_client(argc, argv, nullptr);",
)
cli.write_text(text)
shutil.copyfile(adapter / "auth_user_pass.hpp", cli.parent / "auth_user_pass.hpp")
