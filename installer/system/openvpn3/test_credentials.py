#!/usr/bin/env python3
"""Exercise the compiled credential adapter and real ovpncli without a VPN connection."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class CredentialBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='supermanager-credential-test-')
        root=Path(cls.temp.name)
        src=root/'read.cpp'
        src.write_text('#include "password_stdin.hpp"\n#include <iostream>\nint main(){try{auto secret=supermanager_password_stdin();std::cout<<secret.size();return 0;}catch(const std::exception& e){std::cerr<<e.what();return 1;}}\n')
        cls.exe=root/'read'
        subprocess.run(['/usr/bin/clang++','-std=c++20','-I',str(Path(__file__).parent),str(src),'-o',str(cls.exe)],check=True)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def invoke(self,data):
        return subprocess.run([self.exe],input=data,capture_output=True,timeout=8)
    def test_input_limits_and_no_disclosure(self):
        for size in [1,4096,65536]:
            secret=b'Q'*size
            result=self.invoke(secret)
            self.assertEqual(result.returncode,0)
            self.assertEqual(result.stdout,str(size).encode())
            self.assertNotIn(secret,result.stderr)
        for data in [b'',b'x'*65537,b'abc\n',b'a\0b',b'abc\x7f']:
            self.assertNotEqual(self.invoke(data).returncode,0)
    def test_stalled_pipe_times_out(self):
        with subprocess.Popen([self.exe],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
            child.wait(timeout=8)
            self.assertNotEqual(child.returncode,0)
    def test_real_binary_rejects_password_arguments(self):
        sentinel='NOT-A-REAL-TOKEN-secret-sentinel'
        result=subprocess.run([BINARY,'--password',sentinel],capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(sentinel.encode(),result.stdout+result.stderr)
        self.assertIn(b'Password arguments are disabled',result.stdout+result.stderr)
    def test_real_binary_reads_private_pipe_for_evaluation(self):
        sentinel=b'NOT-A-REAL-TOKEN-sentinel'
        config=Path(self.temp.name)/'eval.ovpn'
        config.write_text('client\ndev tun\nproto tcp-client\nremote 127.0.0.1 1194\nauth-user-pass\nsetenv CLIENT_CERT 0\n')
        result=subprocess.run([BINARY,'--eval','--no-cert','--username','test',
                               '--password-stdin',str(config)],input=sentinel,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertNotIn(sentinel,result.stdout+result.stderr)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    args=parser.parse_args();BINARY=args.binary
    unittest.main(argv=['test_credentials'],verbosity=2)
