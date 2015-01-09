#!/usr/bin/env python
# coding:utf-8

"""A simple python clone for stunnel+squid"""

__version__ = '1.0.0'

import os
import sys
import sysconfig

reload(sys).setdefaultencoding('UTF-8')
sys.dont_write_bytecode = True
sys.path = [(os.path.dirname(__file__) or '.') + '/packages.egg/noarch'] + sys.path + [(os.path.dirname(__file__) or '.') + '/packages.egg/' + sysconfig.get_platform().split('-')[0]]

try:
    __import__('gevent.monkey', fromlist=['.']).patch_all()
except (ImportError, SystemError):
    sys.exit(sys.stderr.write('please install python-gevent\n'))

import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

import socket
import errno
import ssl
import hashlib
import hmac
import struct

import OpenSSL
import gevent
import gevent.server


from proxylib import forward_socket
from proxylib import inflate
from proxylib import random_hostname
from proxylib import SSLConnection
from proxylib import CertUtility
from proxylib import RC4Socket


def readn(sock, n):
    buf = ''
    while n > 0:
        data = sock.recv(n)
        if not data:
            raise socket.error(errno.EPIPE, 'Unexpected EOF')
        n -= len(data)
        buf += data
    return buf


def generate_openssl_context(server_name):
    key, ca = CertUtility(server_name, '', '').create_ca()
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_certificate(ca)
    context.use_privatekey(key)
    return context


class TCPServer(gevent.server.StreamServer):
    """VPS tcp server"""
    def __init__(self, *args, **kwargs):
        self.password = kwargs.pop('password')
        gevent.server.StreamServer.__init__(self, *args, **kwargs)

    def handle(self, sock, address):
        seed = readn(sock, int(hashlib.md5(self.password).hexdigest(), 16) % 11)
        digest = hmac.new(self.password, seed).digest()
        csock = RC4Socket(sock, digest)
        domain = readn(csock, ord(readn(csock, 1)))
        port, = struct.unpack('>H', readn(csock, 2))
        flag = ord(readn(csock, 1))
        data = ''
        do_ssl_handshake = False
        if flag & 0x1:
            raise ValueError('Now UDP is unsupported')
        if flag & 0x2:
            do_ssl_handshake = True
        if flag & 0x4:
            datasize, = struct.unpack('>H', readn(csock, 2))
            data = readn(csock, datasize)
            if flag & 0x8:
                data = inflate(data)
        remote = socket.create_connection((domain, port), timeout=8)
        if do_ssl_handshake:
            remote = ssl.wrap_socket(remote)
        if data:
            remote.sendall(data)
        forward_socket(csock, remote, timeout=60, bufsize=256*1024)


class TLSServer(gevent.server.StreamServer):
    """VPS tls server"""
    def __init__(self, *args, **kwargs):
        self.password = kwargs.pop('password')
        self.ssl_context = generate_openssl_context(random_hostname())
        gevent.server.StreamServer.__init__(self, *args, **kwargs)

    def handle(self, sock, address):
        ssl_sock = SSLConnection(self.ssl_context, sock)
        ssl_sock.set_accept_state()
        ssl_sock.do_handshake()
        password = readn(ssl_sock, len(self.password))
        if password != self.password:
            logging.info("%r send wrong password=%r", address, password)
            ssl_sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
            ssl_sock.close()
            return
        domain = readn(ssl_sock, ord(readn(ssl_sock, 1)))
        port, = struct.unpack('>H', readn(ssl_sock, 2))
        flag = ord(readn(ssl_sock, 1))
        data = ''
        do_ssl_handshake = False
        if flag & 0x1:
            raise ValueError('Now UDP is unsupported')
        if flag & 0x2:
            do_ssl_handshake = True
        if flag & 0x4:
            datasize, = struct.unpack('>H', readn(ssl_sock, 2))
            data = readn(ssl_sock, datasize)
            if flag & 0x8:
                data = inflate(data)
        remote = socket.create_connection((domain, port), timeout=8)
        if do_ssl_handshake:
            remote = ssl.SSLSocket(remote)
        if data:
            remote.sendall(data)
        forward_socket(ssl_sock, remote, timeout=60, bufsize=256*1024)


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    tcp_server = TCPServer(('', 3389), password='123456')
    gevent.spawn(tcp_server.serve_forever)
    tls_server = TLSServer(('', 443), password='123456')
    tls_server.serve_forever()


if __name__ == '__main__':
    main()
