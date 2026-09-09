#!/usr/bin/env python3
"""Build pinned OpenVPN 3 and static dependencies, then extend a runtime snapshot."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from build_runtime import unpack
import validate_runtime
from validate_runtime import validate


def run(args, cwd=None):
    subprocess.run(list(map(str,args)),cwd=cwd,check=True)


def build(a):
    if a.dev: validate_runtime.PREFIX = "/Library/PrivilegedHelperTools/SuperManagerDevVPN"
    if a.output.exists(): raise ValueError('Use a fresh build directory')
    a.output.mkdir(parents=True)
    a.output=a.output.resolve(); work=a.output/'work';work.mkdir()
    records=json.loads((Path(__file__).parent/'sources.lock.json').read_text())['sources']
    with ThreadPoolExecutor(max_workers=4) as pool:
        sources=dict(pool.map(lambda item:unpack(*item,work),records.items()))
    core=sources['openvpn3']
    cli=core/'test/ovpncli/cli.cpp'
    text=cli.read_text()
    patches={
        '#include <stdlib.h>':'#include <stdlib.h>\n#include "supermanager_password_stdin.hpp"',
        '    static const struct option longopts[] = {':'    static const struct option longopts[] = {\n        {.name = "password-stdin", .has_arg = no_argument, .flag = nullptr, .val = 1001},',
        "                case 'p':\n                    password = optarg;\n                    break;":
        '''                case 1001:
                    password = supermanager_password_stdin();
                    break;
                case 'p':
                    throw std::runtime_error("Password arguments are disabled; use --password-stdin");''',
        '        std::cout << "--password, -p        : password\\n";':
        '        std::cout << "--password-stdin      : read bounded credential from stdin until EOF\\n";',
    }
    for old,new in patches.items():
        if text.count(old)!=1:raise ValueError('Upstream credential adapter changed')
        text=text.replace(old,new)
    cli.write_text(text)
    shutil.copy2(Path(__file__).parent/'password_stdin.hpp',core/'test/ovpncli/supermanager_password_stdin.hpp')
    # Curated wrapper target, without upstream agents, test fetches, or package discovery.
    # Dependencies are all from the checked archives or the prior pinned OpenSSL build.
    cmake=a.output/'CMakeLists.txt'
    cmake.write_text('''cmake_minimum_required(VERSION 3.20)
project(SuperManagerOpenVPN3 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_library(lz4 STATIC "${LZ4}/lib/lz4.c" "${LZ4}/lib/lz4hc.c" "${LZ4}/lib/lz4frame.c" "${LZ4}/lib/xxhash.c")
add_library(xkey STATIC "${CORE}/openvpn/openssl/xkey/xkey_helper.c" "${CORE}/openvpn/openssl/xkey/xkey_provider.c")
target_include_directories(xkey PRIVATE "${SSL}/include")
target_compile_definitions(xkey PRIVATE USE_OPENSSL)
add_executable(openvpn3 "${CORE}/test/ovpncli/cli.cpp" "${CORE}/openvpn/crypto/data_epoch.cpp")
target_include_directories(openvpn3 PRIVATE "${CORE}" "${ASIO}/include" "${FMT}/include" "${LZ4}/lib" "${SSL}/include")
target_compile_definitions(openvpn3 PRIVATE ASIO_STANDALONE USE_ASIO HAVE_LZ4 USE_OPENSSL FMT_HEADER_ONLY ENABLE_EXTERNAL_PKI)
target_link_libraries(openvpn3 xkey lz4 "${SSL}/lib/libssl.a" "${SSL}/lib/libcrypto.a" "-framework CoreFoundation" "-framework IOKit" "-framework CoreServices" "-framework SystemConfiguration")
''')
    run([a.cmake,'-S',a.output,'-B',a.output/'build','-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=/usr/bin/clang','-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
         '-DCMAKE_OSX_DEPLOYMENT_TARGET=14.0','-DCMAKE_SKIP_RPATH=ON',
         '-DCORE='+str(core),'-DASIO='+str(sources['asio']),'-DFMT='+str(sources['fmt']),
         '-DLZ4='+str(sources['lz4']),'-DSSL='+str(a.openssl.resolve())])
    run([a.cmake,'--build',a.output/'build','--parallel','4'])
    runtime=a.output/'runtime';shutil.copytree(a.runtime,runtime,symlinks=True)
    shutil.copy2(a.output/'build/openvpn3',runtime/'bin/openvpn3')
    for name,source in sources.items():
        target=runtime/'licenses'/('openvpn3-'+name);target.mkdir()
        licenses=[p for p in source.glob('*') if p.is_file() and p.name.upper().startswith(('LICENSE','COPYING'))]
        if (source/'LICENSES').is_dir():
            licenses+=list((source/'LICENSES').glob('*.txt'))
        if name=='asio':licenses.append(source/'COPYING')
        if name=='lz4':licenses.append(source/'lib/LICENSE')
        if not licenses:raise ValueError('Missing dependency license: '+name)
        for path in licenses:
            if path.is_file():shutil.copy2(path,target/path.name)
    for path in runtime.rglob("*"):
        if path.is_file(): path.chmod(0o755 if path.stat().st_mode & 0o111 and "licenses" not in path.parts else 0o644)
    manifest=json.loads(a.manifest.read_text())
    manifest['sources']+=list(records.values())
    manifest['local_adapter_sha256']=hashlib.sha256((Path(__file__).parent/'password_stdin.hpp').read_bytes()).hexdigest()
    manifest['files']={p.relative_to(runtime).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime.rglob('*') if p.is_file()}
    result=a.output/'manifest.json';result.write_text(json.dumps(manifest,indent=2)+'\n')
    validate(runtime,result)
    print('Validated OpenVPN 3 runtime: '+str(runtime))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['runtime','manifest','openssl','output','cmake']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--dev', action='store_true')
    build(p.parse_args())
