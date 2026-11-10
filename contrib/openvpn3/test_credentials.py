#!/usr/bin/env python3
"""Exercise the built CLI's credential boundary without opening a tunnel."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--binary", required=True, type=pathlib.Path)
parser.add_argument("--ca", type=pathlib.Path)
parser.add_argument("--openssl", type=pathlib.Path)
args = parser.parse_args()
binary = args.binary.resolve()
sentinel = "supermanager-test-token-DO-NOT-LOG"
checks = 0


def run(arguments, accepted, environment=None):
    global checks
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                            timeout=15, env=environment)
    output = result.stdout + result.stderr
    assert sentinel.encode() not in output, "credential leaked to CLI output"
    assert (result.returncode == 0) == accepted, (arguments[0], result.returncode, output[:500])
    checks += 1
    return output


with tempfile.TemporaryDirectory(prefix="supermanager-openvpn3-test-") as temporary:
    root = pathlib.Path(temporary)
    credentials = root / "credentials"

    def write(body, mode=0o600):
        credentials.write_bytes(body)
        credentials.chmod(mode)

    write(f"AzureAD\n{sentinel}\n".encode())
    assert b"auth-file-v1" in run(["--auth-user-pass", credentials, "--version"], True)
    run(["-a", credentials, "--version"], True)  # shipped 1.8.25 helper compatibility
    run(["--auto-sess", "--version"], True)  # upstream option remains unambiguous
    run(["--password", sentinel, "--version"], False)
    run(["-p", sentinel, "--version"], False)
    for malformed in (b"", b"AzureAD\n", b"\ntoken\n", b"AzureAD\ntoken\nextra\n",
                      b"AzureAD\nto\x00ken\n", b"AzureAD\nto\rken\n", b"AzureAD\nto\tken\n",
                      b"AzureAD\n" + b"x" * (1024 * 1024)):
        write(malformed)
        run(["--auth-user-pass", credentials, "--version"], False)
    write(f"AzureAD\n{sentinel}\n".encode(), 0o644)
    run(["--auth-user-pass", credentials, "--version"], False)
    credentials.chmod(0o600)
    link = root / "symlink"
    link.symlink_to(credentials)
    run(["--auth-user-pass", link, "--version"], False)
    fifo = root / "fifo"
    os.mkfifo(fifo, 0o600)
    run(["--auth-user-pass", fifo, "--version"], False)
    run(["--auth-user-pass", root, "--version"], False)

    if args.ca:
        profile = root / "test.ovpn"
        profile.write_text("client\ndev tun\nproto tcp-client\nremote 127.0.0.1 9\n"
                           "auth-user-pass\nremote-cert-tls server\n<ca>\n"
                           + args.ca.read_text() + "\n</ca>\n")
        output = run(["--auth-user-pass", credentials, "--no-cert", "--eval", profile], True)
        assert b"EVAL PROFILE\nerror=0\n" in output, output[:1000]

    if args.openssl:
        # A harmless provider probe creates a marker if OpenSSL loads code
        # through a supplied config. Prove the probe works in Homebrew's
        # OpenSSL, then prove the managed runtime ignores those overrides.
        marker = root / "provider-loaded"
        module = root / "probe.dylib"
        source = root / "probe.c"
        source.write_text('#include <stdio.h>\n'
                          '__attribute__((constructor)) static void loaded(void) {'
                          'FILE *f=fopen(' + json.dumps(str(marker)) + ',"w");'
                          'if(f){fputs("loaded",f);fclose(f);}}\n'
                          'int OSSL_provider_init(void*a,const void*b,const void**c,void**d)'
                          '{return 0;}\n')
        subprocess.run(["/usr/bin/clang", "-dynamiclib", str(source), "-o", str(module)],
                       check=True, capture_output=True, timeout=30)
        config = root / "openssl.cnf"
        config.write_text('openssl_conf = init\n[init]\nproviders = providers\n'
                          '[providers]\nprobe = probe\n[probe]\nmodule = '
                          + str(module) + '\nactivate = 1\n')
        environment = os.environ | {"OPENSSL_CONF": str(config), "OPENSSL_MODULES": str(root)}
        subprocess.run([str(args.openssl), "list", "-providers"], env=environment,
                       capture_output=True, timeout=15)
        assert marker.exists(), "OpenSSL provider probe did not exercise config loading"
        marker.unlink()
        run(["--version"], True, environment)
        assert not marker.exists(), "managed runtime loaded a user-supplied OpenSSL provider"

print(f"OpenVPN 3 offline credential checks passed ({checks})")
