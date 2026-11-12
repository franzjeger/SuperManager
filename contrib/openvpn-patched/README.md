# openvpn-patched (Arch Linux)

Azure VPN with Entra ID sends the access token as the `auth-user-pass`
password. Stock openvpn, every version up to and including 2.7.9 and
`master`, sends username, password and peer info in one 2048-byte TLS buffer
(`TLS_CHANNEL_BUF_SIZE`), and a large token does not fit:

    WARNING: Failed to write auth password to TLS buffer
    TLS Error: Key Method #2 write failed

This PKGBUILD is Arch's `openvpn` package with that buffer raised to 8192
bytes. It is the same change as the macOS helper's `openvpn-patched`. It
installs only `/usr/bin/openvpn-patched`, next to the regular `openvpn`
package, and the daemon's Azure backend prefers it when it is present.

The source is the signed upstream tag, verified against the two OpenVPN
release keys in `keys/pgp`, which come from Arch's packaging. To build and
install:

    export GNUPGHOME="$(mktemp -d)"     # keep the release keys out of your keyring
    gpg --import keys/pgp/*.asc
    makepkg --cleanbuild
    sudo pacman -U openvpn-patched-*-x86_64.pkg.tar.zst

When Arch moves `openvpn` to a new release, update `pkgver` and the source
checksum from Arch's PKGBUILD and rebuild.

`options=('!lto')`: under makepkg's `-flto=auto`, `tls_crypt_testdriver`
fails, because LTO breaks the unit tests' `-Wl,--wrap` mocks. It fails that
way with or without the buffer change, and passes without LTO.
