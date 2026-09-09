#!/usr/bin/env python3
"""Build isolated macOS VPN sources with protected install paths; never install globally.
Requires Xcode CLI tools, make, Perl, pkg-config and a Go compiler supplied via --go.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request
from validate_runtime import PREFIX, validate


def run(argv, cwd, env):
    print('+', ' '.join(map(str, argv)), flush=True)
    subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True)


def unpack(name, record, work, cache=None):
    archive = work / (name + '.archive')
    # Hash pin is committed separately from the endpoint response.
    cached = cache / (name + '.archive') if cache else None
    if cached and cached.is_file():
        shutil.copyfile(cached, archive)
    else:
        request = urllib.request.Request(record['url'], headers={'User-Agent': 'SuperManager-runtime-build/1'})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open('wb') as out:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > 200 * 1024 * 1024: raise ValueError('Source archive too large')
                out.write(block)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != record['sha256']:
        raise ValueError(f'Source checksum mismatch: {name}')
    destination = work / name
    destination.mkdir()
    with tarfile.open(archive) as tar:
        # Reject links and path escapes before extraction. Source distributions
        # must contain regular files/directories; never unpack device files.
        members = [m for m in tar.getmembers() if not (
            name == 'wireguard-tools' and m.issym()
            and m.name.endswith('/src/wg-quick/wg') and m.linkname == '../wg')]
        # That upstream developer convenience link points at the not-yet-built
        # wg binary. Installation uses the actual src/wg output instead.
        for entry in members:
            candidate = destination / entry.name
            if (not candidate.resolve().is_relative_to(destination.resolve())
                    or not (entry.isdir() or entry.isfile())):
                raise ValueError(f'Unsafe archive member: {entry.name}')
        tar.extractall(destination, members=members)
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir(): raise ValueError('Expected one archive root')
    return name, roots[0]


def build(args):
    if platform.system() != 'Darwin': raise ValueError('Build on macOS')
    if args.output.exists(): raise ValueError('Use a fresh output directory')
    args.output.mkdir(parents=True)
    output = args.output.resolve()
    work = output / 'work'; work.mkdir()
    records = json.loads((Path(__file__).parent / 'sources.lock.json').read_text())['sources']
    with ThreadPoolExecutor(max_workers=4) as pool:
        sources = dict(pool.map(lambda item: unpack(*item, work, args.source_cache), records.items()))
    dest = output / 'dest'; dest.mkdir()
    prefix = dest / PREFIX.lstrip('/')
    env = {k: v for k, v in os.environ.items() if k not in {
        'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
        'CPATH', 'LIBRARY_PATH', 'PKG_CONFIG_PATH', 'SDKROOT'}}
    env.update(CC='/usr/bin/clang', CFLAGS='-O2', LDFLAGS='',
               MACOSX_DEPLOYMENT_TARGET='14.0', PKG_CONFIG_LIBDIR=str(prefix / 'lib/pkgconfig'))
    jobs = str(min(os.cpu_count() or 2, 8))
    def make(name, targets): run(['/usr/bin/make', '-j' + jobs, *targets], sources[name], env)
    def configure(name, options): run(['./configure', '--prefix=' + PREFIX, *options], sources[name], env)
    # Build OpenSSL statically: no Homebrew dylibs or external provider modules.
    openssl_target = 'darwin64-arm64-cc' if platform.machine() == 'arm64' else 'darwin64-x86_64-cc'
    run(['/usr/bin/perl', './Configure', openssl_target, 'no-shared', 'no-tests', 'no-module',
         '--prefix=' + PREFIX, '--openssldir=' + PREFIX + '/etc/ssl'], sources['openssl@3'], env)
    make('openssl@3', [])
    make('openssl@3', ['install_sw', 'DESTDIR=' + str(dest)])
    env.update(OPENSSL_CFLAGS='-I' + str(prefix / 'include'),
               OPENSSL_LIBS=f'{prefix}/lib/libssl.a {prefix}/lib/libcrypto.a',
               CPPFLAGS='-I' + str(prefix / 'include'), LDFLAGS='-L' + str(prefix / 'lib'))
    bash_config = sources['bash'] / 'config-top.h'
    defaults = bash_config.read_text()
    patches = {
        '/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.':
            PREFIX + '/bin:/usr/bin:/usr/sbin:/bin:/sbin',
        '/usr/local/lib/bash:/usr/lib/bash:/opt/local/lib/bash:/usr/pkg/lib/bash:/opt/pkg/lib/bash:.':
            PREFIX + '/lib/bash',
    }
    for old, new in patches.items():
        if defaults.count(old) != 1: raise ValueError('Bash default paths changed; review source patch')
        defaults = defaults.replace(old, new)
    bash_config.write_text(defaults)
    configure('bash', ['--disable-nls', '--without-bash-malloc'])
    make('bash', []); make('bash', ['install', 'DESTDIR=' + str(dest)])
    configure('openvpn', ['--disable-lzo', '--disable-lz4', '--disable-pkcs11',
                         '--disable-dco', '--disable-plugin-auth-pam', '--with-crypto-library=openssl'])
    make('openvpn', []); make('openvpn', ['install', 'DESTDIR=' + str(dest)])
    configure('strongswan', ['--disable-defaults', '--enable-static', '--disable-shared', '--enable-monolithic',
        '--enable-charon', '--enable-swanctl', '--enable-vici', '--enable-openssl', '--enable-random',
        '--enable-nonce', '--enable-x509', '--enable-pubkey', '--enable-pem', '--enable-pkcs1',
        '--enable-kernel-pfroute', '--enable-kernel-pfkey', '--enable-socket-default',
        '--enable-eap-identity', '--enable-eap-mschapv2', '--enable-md4', '--enable-des', '--enable-resolve', '--enable-updown'])
    make('strongswan', []); make('strongswan', ['install', 'DESTDIR=' + str(dest)])
    run(['/usr/bin/make', '-C', 'src', '-j' + jobs, 'WITH_WGQUICK=yes', 'WITH_BASHCOMPLETION=no'], sources['wireguard-tools'], env)
    run(['/usr/bin/make', '-C', 'src', 'install', 'PREFIX=' + PREFIX, 'DESTDIR=' + str(dest),
         'WITH_WGQUICK=yes', 'WITH_BASHCOMPLETION=no'], sources['wireguard-tools'], env)
    go_env = dict(env, CGO_ENABLED='0', GOTOOLCHAIN='local', GOOS='darwin',
                  GOARCH='arm64' if platform.machine() == 'arm64' else 'amd64')
    run([args.go, 'build', '-mod=readonly', '-trimpath', '-ldflags=-s -w',
         '-o', prefix / 'bin/wireguard-go', '.'], sources['wireguard-go'], go_env)
    runtime = output / 'runtime'; runtime.mkdir()
    # Curated output; no development archives, headers, manpages or extra tools.
    for relative in ('bin/bash', 'bin/wg', 'bin/wg-quick', 'bin/wireguard-go', 'sbin/openvpn',
                     'bin/swanctl', 'libexec/ipsec/charon'):
        target = runtime / relative; target.parent.mkdir(parents=True, exist_ok=True)
        source_relative = 'sbin/swanctl' if relative == 'bin/swanctl' else relative
        shutil.copyfile(prefix / source_relative, target); target.chmod(0o755)
    (runtime / 'lib/ipsec/plugins').mkdir(parents=True)
    (runtime / 'etc/swanctl/conf.d').mkdir(parents=True)
    (runtime / 'etc/swanctl/swanctl.d').mkdir()
    # Monolithic strongSwan has no external dlopen plugins. Mutable connection
    # fragments live only under this protected root-owned runtime.
    (runtime / 'etc/strongswan.conf').write_text('charon {\n  load_modular = no\n}\n')
    (runtime / 'etc/swanctl/swanctl.conf').write_text('include conf.d/*.conf\ninclude swanctl.d/*.conf\n')
    quick = runtime / 'bin/wg-quick'
    script = quick.read_text().splitlines()
    script[0] = '#!' + PREFIX + '/bin/bash'
    body = '\n'.join(script) + '\n'
    old_search = 'CONFIG_SEARCH_PATHS=( /etc/wireguard /usr/local/etc/wireguard )'
    old_path = 'export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${SELF%/*}:$PATH"'
    if body.count(old_search) != 1 or body.count(old_path) != 1:
        raise ValueError('Upstream wg-quick layout changed; review the packaging patch')
    body = body.replace(old_search, 'CONFIG_SEARCH_PATHS=( /private/etc/wireguard )')
    body = body.replace(old_path, f'export PATH="{PREFIX}/bin:/usr/bin:/bin:/usr/sbin:/sbin"')
    quick.write_text(body)
    licenses = runtime / 'licenses'; licenses.mkdir()
    for name, source in sources.items():
        license_file = next((source / name for name in ('COPYING', 'LICENSE', 'LICENSE.txt', 'LICENSE.md')
                             if (source / name).is_file()), None)
        if license_file is None: raise ValueError(f'Missing license text: {name}')
        shutil.copyfile(license_file, licenses / (name + '.txt'))
    manifest = {'schema': 1, 'architecture': platform.machine(), 'sources': list(records.values()),
                'files': {p.relative_to(runtime).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in runtime.rglob('*') if p.is_file()}}
    manifest_path = output / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    validate(runtime, manifest_path)
    print(f'Validated runtime: {runtime}. Source archives and build tree retained in {work}.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--source-cache', type=Path)
    build(parser.parse_args())
