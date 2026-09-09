# Managed OpenVPN 3 / Azure runtime

This extends an already built base VPN runtime. It builds the reviewed OpenVPN
3 client from a pinned commit and links pinned Asio/fmt/LZ4 headers/sources and
the base runtime's static OpenSSL. No Homebrew libraries are loaded at runtime.
CMake is only a build tool. `sources.lock.json` records source URLs, hashes and
licenses; OpenVPN 3 upstream is https://github.com/OpenVPN/openvpn3.

The small local adapter adds `--password-stdin`, bounds input to 64 KiB and five
seconds, rejects empty/control-character input, and disables password argv.
It does not change TLS verification. `--no-cert` disables the Azure client's
certificate requirement, not verification of the server's certificate.
Source layout drift fails the patch step. The runtime manifest records the local
adapter hash and all final files. The signed package signs the new executable
and includes source licenses alongside it.

For a local Dev build, after preparing and building the base Dev runtime:

```sh
python3 installer/system/openvpn3/build.py \
  --runtime /tmp/base/runtime \
  --manifest /tmp/base/manifest.json \
  --openssl /tmp/base/dest/Library/PrivilegedHelperTools/SuperManagerDevVPN \
  --output /tmp/azure-runtime \
  --cmake /opt/homebrew/bin/cmake --dev
python3 installer/system/openvpn3/test_credentials.py \
  --binary /tmp/azure-runtime/runtime/bin/openvpn3
```

For production-channel source builds omit `--dev`, and use the corresponding
`SuperManagerVPN` base build. Use the extension's returned `runtime` and
`manifest.json` with the correct channel's `installer/system/build.py`. Do not
replace a live runtime directory manually. Package build numbers must increase;
quit the app and disconnect its VPN processes before an update.

Azure calls the helper with the validated `engine: "openvpn3"` enum. Calls that
omit it retain OpenVPN 2. The helper snapshots validated configuration, creates
0600 logs, delivers the token through stdin and tracks the child PID. Status and
disconnect require the managed executable and exact profile configuration or
daemon argument; a matching UUID or reused PID alone is insufficient.

Verification on macOS ARM64: native source build and runtime validation; OpenVPN
3 crypto self-test; four credential-boundary tests; 87 helper tests; five Dev
snapshot tests; Swift release build. The operator's actual Azure profile passed
both input validation and OpenVPN 3 evaluation without a network connection.
This is not evidence of a completed live Azure tunnel or public notarization.
