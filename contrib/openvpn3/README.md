# Managed OpenVPN 3 runtime

`scripts/build-openvpn3-runtime.sh OUT_DIR` builds a pinned OpenVPN 3 source
archive and checks its SHA-256 before compiling. OpenSSL, LZ4, fmt and Asio
come from pinned, hash-checked source archives as well. The compiled static
libraries and runtime target macOS 14.0; `check_deployment.py` rejects a newer
minimum OS in any archive object or the executable. Homebrew supplies only
CMake. The executable is rejected if `otool -L` reports a dependency outside
macOS's system libraries or if it has any runtime search path. It disables
OpenSSL configuration loading and points provider loading at `/var/empty` so
OpenSSL config and provider modules from writable directories are not loaded
as root.

The local adapter adds `--auth-user-pass FILE` for the helper's private
`username LF password LF` file. It accepts at most 1 MiB, requires a regular
file owned by the effective user with no group/other permissions, refuses
symlinks, and rejects empty fields, extra lines and control bytes. Errors never
include the file's contents. Password argv (`--password`/`-p`) is disabled.
The adapter does not change server certificate verification. `--no-cert`
retains upstream's meaning: no client certificate for token authentication.

The shipped 1.8.25 helper accidentally used `-a FILE`, while upstream `-a`
means auto-session. The managed runtime accepts `-a FILE` as a compatibility
alias for its auth file option; the unambiguous upstream `--auto-sess` option
still works. New helpers use `--auth-user-pass FILE`.

The build runs OpenVPN's self-test entry point and the offline credential checks,
including this compatibility invocation, malformed files, permission checks,
symlinks, FIFOs, argument-based passwords and profile evaluation. A harmless
provider probe also checks that user-supplied OpenSSL config cannot load code
in the managed runtime. They make no
network connection. They can also be run separately:

```sh
python3 contrib/openvpn3/test_credentials.py --binary /path/to/openvpn3
```

Upstream's OpenSSL self-test entry point currently returns an empty string;
its successful exit is only a startup check, not a cryptographic test suite.
The recipe builds its dependencies from source rather than using Homebrew
bottles, whose object files can require a newer macOS even when the final
executable is linked with an older deployment target. The deployment check
covers object metadata; running on the minimum supported OS is a separate
release validation step.

The binary and source licenses are copied to the caller's output directory;
the caller signs the binary with `com.sybr.supermanager.vpn.openvpn3` before
the existing helper's `vpn_runtime_install` verifies and installs it. This
script never writes into a live root-owned runtime itself.
