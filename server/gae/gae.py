#!/usr/bin/env python
# coding:utf-8

__version__ = '3.2.0'
__password__ = ''
__hostsdeny__ = ()  # __hostsdeny__ = ('.youtube.com', '.youku.com')

import os
import re
import time
import struct
import zlib
import base64
import logging
import urlparse
import httplib
import io
import string

from google.appengine.api import urlfetch
from google.appengine.api.taskqueue.taskqueue import MAX_URL_LENGTH
from google.appengine.runtime import apiproxy_errors

URLFETCH_MAX = 2
URLFETCH_MAXSIZE = 4*1024*1024
URLFETCH_DEFLATE_MAXSIZE = 4*1024*1024
URLFETCH_TIMEOUT = 30

def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message From FetchServer</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)


try:
    from Crypto.Cipher.ARC4 import new as RC4Cipher
except ImportError:
    logging.warn('Load Crypto.Cipher.ARC4 Failed, Use Pure Python Instead.')
    class RC4Cipher(object):
        def __init__(self, key):
            x = 0
            box = range(256)
            for i, y in enumerate(box):
                x = (x + y + ord(key[i % len(key)])) & 0xff
                box[i], box[x] = box[x], y
            self.__box = box
            self.__x = 0
            self.__y = 0
        def encrypt(self, data):
            out = []
            out_append = out.append
            x = self.__x
            y = self.__y
            box = self.__box
            for char in data:
                x = (x + 1) & 0xff
                y = (y + box[x]) & 0xff
                box[x], box[y] = box[y], box[x]
                out_append(chr(ord(char) ^ box[(box[x] + box[y]) & 0xff]))
            self.__x = x
            self.__y = y
            return ''.join(out)


def inflate(data):
    return zlib.decompress(data, -zlib.MAX_WBITS)


def deflate(data):
    return zlib.compress(data)[2:-4]


def format_response(status, headers, content):
    if content:
        headers.pop('content-length', None)
        headers['Content-Length'] = str(len(content))
    data = 'HTTP/1.1 %d %s\r\n%s\r\n\r\n%s' % (status, httplib.responses.get(status, 'Unknown'), '\r\n'.join('%s: %s' % (k.title(), v) for k, v in headers.items()), content)
    data = deflate(data)
    return struct.pack('!h', len(data)) + data

def application(environ, start_response):
    ps_headers = dict((x, environ[x]) for x in environ if x.startswith('HTTP_X_GOA_PS'))
    options = environ.get('HTTP_X_GOA_OPTIONS', '')
    start_response('200 OK', [('Content-Type', 'image/gif')])

    if environ['REQUEST_METHOD'] == 'GET' and not ps_headers:
        timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/2**28
        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
        yield format_response(200, {'Content-Type': 'text/plain; charset=utf-8'}, 'GoAgent Python Server %s works, deployed at %s\n' % (__version__, ctime))
        raise StopIteration

    if 'rc4' in options and not __password__:
        yield format_response(400, {'Content-Type': 'text/html; charset=utf-8'}, message_html('400 Bad Request', 'Bad Request (options) - please set __password__ in gae.py', 'please set __password__ and upload gae.py again'))
        raise StopIteration

    try:
        if ps_headers:
            metadata = inflate(base64.b64decode(ps_headers['HTTP_X_GOA_PS1']))
            payload = inflate(base64.b64decode(ps_headers['HTTP_X_GOA_PS2'])) if 'HTTP_X_GOA_PS2' in ps_headers else ''
        else:
            wsgi_input = environ['wsgi.input']
            input_data = wsgi_input.read(int(environ.get('CONTENT_LENGTH', '0')))
            if 'rc4' in options:
                input_data = RC4Cipher(__password__).encrypt(input_data)
            metadata_length, = struct.unpack('!h', input_data[:2])
            metadata = inflate(input_data[2:2+metadata_length])
            payload = input_data[2+metadata_length:]
        headers = dict(x.split(':', 1) for x in metadata.splitlines() if x)
        method = headers.pop('G-Method')
        url = headers.pop('G-Url')
    except (zlib.error, KeyError, ValueError):
        import traceback
        yield format_response(500, {'Content-Type': 'text/html; charset=utf-8'}, message_html('500 Internal Server Error', 'Bad Request (metadata) - Possible Wrong Password', '<pre>%s</pre>' % traceback.format_exc()))
        raise StopIteration

    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    if 'Content-Encoding' in headers and payload:
        if headers['Content-Encoding'] == 'deflate':
            payload = inflate(payload)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

    if __password__ and __password__ != kwargs.get('password', ''):
        yield format_response(403, {'Content-Type': 'text/html; charset=utf-8'}, message_html('403 Wrong password', 'Wrong password(%r)' % kwargs.get('password', ''), 'GoAgent proxy.ini password is wrong!'))
        raise StopIteration

    netloc = urlparse.urlparse(url).netloc

    if __hostsdeny__ and netloc.endswith(__hostsdeny__):
        yield format_response(403, {'Content-Type': 'text/html; charset=utf-8'}, message_html('403 Hosts Deny', 'Hosts Deny(%r)' % netloc, detail='url=%r' % url))
        raise StopIteration

    if len(url) > MAX_URL_LENGTH:
        yield format_response(400, {'Content-Type': 'text/html; charset=utf-8'}, message_html('400 Bad Request', 'length of URL too long(greater than %r)' % MAX_URL_LENGTH, detail='url=%r' % url))
        raise StopIteration

    if netloc.startswith(('127.0.0.', '::1', 'localhost')):
        yield format_response(400, {'Content-Type': 'text/html; charset=utf-8'}, message_html('GoAgent %s is Running' % __version__, 'Now you can visit some websites', ''.join('<a href="https://%s/">%s</a><br/>' % (x, x) for x in ('google.com', 'mail.google.com'))))
        raise StopIteration

    fetchmethod = getattr(urlfetch, method, None)
    if not fetchmethod:
        yield format_response(405, {'Content-Type': 'text/html; charset=utf-8'}, message_html('405 Method Not Allowed', 'Method Not Allowed: %r' % method, detail='Method Not Allowed URL=%r' % url))
        raise StopIteration

    timeout = int(kwargs.get('timeout', URLFETCH_TIMEOUT))
    validate_certificate = bool(int(kwargs.get('validate', 0)))
    maxsize = int(kwargs.get('maxsize', 0))
    # https://www.freebsdchina.org/forum/viewtopic.php?t=54269
    accept_encoding = headers.get('Accept-Encoding', '') or headers.get('Bccept-Encoding', '')
    errors = []
    for i in xrange(int(kwargs.get('fetchmax', URLFETCH_MAX))):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, allow_truncated=False, follow_redirects=False, deadline=timeout, validate_certificate=validate_certificate)
            break
        except apiproxy_errors.OverQuotaError as e:
            time.sleep(5)
        except urlfetch.DeadlineExceededError as e:
            errors.append('%r, timeout=%s' % (e, timeout))
            logging.error('DeadlineExceededError(timeout=%s, url=%r)', timeout, url)
            time.sleep(1)
            timeout *= 2
        except urlfetch.DownloadError as e:
            errors.append('%r, timeout=%s' % (e, timeout))
            logging.error('DownloadError(timeout=%s, url=%r)', timeout, url)
            time.sleep(1)
            timeout *= 2
        except urlfetch.ResponseTooLargeError as e:
            errors.append('%r, timeout=%s' % (e, timeout))
            response = e.response
            logging.error('ResponseTooLargeError(timeout=%s, url=%r) response(%r)', timeout, url, response)
            m = re.search(r'=\s*(\d+)-', headers.get('Range') or headers.get('range') or '')
            if m is None:
                headers['Range'] = 'bytes=0-%d' % (maxsize or URLFETCH_MAXSIZE)
            else:
                headers.pop('Range', '')
                headers.pop('range', '')
                start = int(m.group(1))
                headers['Range'] = 'bytes=%s-%d' % (start, start+(maxsize or URLFETCH_MAXSIZE))
            timeout *= 2
        except urlfetch.SSLCertificateError as e:
            errors.append('%r, should validate=0 ?' % e)
            logging.error('%r, timeout=%s', e, timeout)
        except Exception as e:
            errors.append(str(e))
            if i == 0 and method == 'GET':
                timeout *= 2
    else:
        error_string = '<br />\n'.join(errors)
        if not error_string:
            logurl = 'https://appengine.google.com/logs?&app_id=%s' % os.environ['APPLICATION_ID']
            error_string = 'Internal Server Error. <p/>try <a href="javascript:window.location.reload(true);">refresh</a> or goto <a href="%s" target="_blank">appengine.google.com</a> for details' % logurl
        yield format_response(502, {'Content-Type': 'text/html; charset=utf-8'}, message_html('502 Urlfetch Error', 'Python Urlfetch Error: %r' % method, error_string))
        raise StopIteration

    #logging.debug('url=%r response.status_code=%r response.headers=%r response.content[:1024]=%r', url, response.status_code, dict(response.headers), response.content[:1024])

    status_code = int(response.status_code)
    data = response.content
    response_headers = response.headers
    content_type = response_headers.get('content-type', '')
    if status_code == 200 and maxsize and len(data) > maxsize and response_headers.get('accept-ranges', '').lower() == 'bytes' and int(response_headers.get('content-length', 0)):
        status_code = 206
        response_headers['Content-Range'] = 'bytes 0-%d/%d' % (maxsize-1, len(data))
        data = data[:maxsize]
    if status_code == 200 and 'content-encoding' not in response_headers and 512 < len(data) < URLFETCH_DEFLATE_MAXSIZE and content_type.startswith(('text/', 'application/json', 'application/javascript')):
        if 'gzip' in accept_encoding:
            response_headers['Content-Encoding'] = 'gzip'
            compressobj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
            dataio = io.BytesIO()
            dataio.write('\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff')
            dataio.write(compressobj.compress(data))
            dataio.write(compressobj.flush())
            dataio.write(struct.pack('<LL', zlib.crc32(data) & 0xFFFFFFFFL, len(data) & 0xFFFFFFFFL))
            data = dataio.getvalue()
        elif 'deflate' in accept_encoding:
            response_headers['Content-Encoding'] = 'deflate'
            data = deflate(data)
    response_headers['Content-Length'] = str(len(data))
    if 'rc4' not in options:
        yield format_response(status_code, response_headers, '')
        yield data
    else:
        cipher = RC4Cipher(__password__)
        yield cipher.encrypt(format_response(status_code, response_headers, ''))
        yield cipher.encrypt(data)


def legacy_application(environ, start_response):
    ps_headers = dict((x, environ[x]) for x in environ if x.startswith('HTTP_X_GOA_PS'))
    options = environ.get('HTTP_X_GOA_OPTIONS', '')

    if environ['REQUEST_METHOD'] == 'GET' and not ps_headers:
        timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/2**28
        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
        text = u'GoAgent Python Server %s \u5df2\u7ecf\u5728\u5de5\u4f5c\u4e86\uff0c\u90e8\u7f72\u65f6\u95f4 %s\n' % (__version__, ctime)
        start_response('200 OK', [('Content-Type', 'text/plain; charset=utf-8')])
        yield text.encode('utf8')
        raise StopIteration

    if 'rc4' in options and not __password__:
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '403')])
        yield message_html('400 Bad Request', 'Bad Request (options) - please set __password__ in gae.py', 'please set __password__ and upload gae.py again')
        raise StopIteration

    try:
        if ps_headers:
            metadata = inflate(base64.b64decode(ps_headers['HTTP_X_GOA_PS1']))
            payload = inflate(base64.b64decode(ps_headers['HTTP_X_GOA_PS2'])) if 'HTTP_X_GOA_PS2' in ps_headers else ''
        else:
            wsgi_input = environ['wsgi.input']
            input_data = wsgi_input.read(int(environ.get('CONTENT_LENGTH', '0')))
            if 'rc4' in options:
                input_data = RC4Cipher(__password__).encrypt(input_data)
            metadata_length, = struct.unpack('!h', input_data[:2])
            metadata = inflate(input_data[2:2+metadata_length])
            payload = input_data[2+metadata_length:]
        headers = dict(x.split(':', 1) for x in metadata.splitlines() if x)
        method = headers.pop('G-Method')
        url = headers.pop('G-Url')
    except (zlib.error, KeyError, ValueError):
        import traceback
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '400')])
        yield message_html('500 Internal Server Error', 'Bad Request (metadata) - Possible Wrong Password', '<pre>%s</pre>' % traceback.format_exc())
        raise StopIteration

    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    if 'Content-Encoding' in headers and payload:
        if headers['Content-Encoding'] == 'deflate':
            payload = inflate(payload)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')
    #logging.info('request headers=%s', headers)

    if __password__ and __password__ != kwargs.get('password', ''):
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '403')])
        yield message_html('403 Wrong password', 'Wrong password(%r)' % kwargs.get('password', ''), 'GoAgent proxy.ini password is wrong!')
        raise StopIteration

    netloc = urlparse.urlparse(url).netloc

    if __hostsdeny__ and netloc.endswith(__hostsdeny__):
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '403')])
        yield message_html('403 Hosts Deny', 'Hosts Deny(%r)' % netloc, detail='url=%r' % url)
        raise StopIteration

    if len(url) > MAX_URL_LENGTH:
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '400')])
        yield message_html('400 Bad Request', 'length of URL too long(greater than %r)' % MAX_URL_LENGTH, detail='url=%r' % url)
        raise StopIteration

    if netloc.startswith(('127.0.0.', '::1', 'localhost')):
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '400')])
        html = ''.join('<a href="https://%s/">%s</a><br/>' % (x, x) for x in ('google.com', 'mail.google.com'))
        yield message_html('GoAgent %s is Running' % __version__, 'Now you can visit some websites', html)
        raise StopIteration

    fetchmethod = getattr(urlfetch, method, None)
    if not fetchmethod:
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '405')])
        yield message_html('405 Method Not Allowed', 'Method Not Allowed: %r' % method, detail='Method Not Allowed URL=%r' % url)
        raise StopIteration

    deadline = URLFETCH_TIMEOUT
    validate_certificate = bool(int(kwargs.get('validate', 0)))
    maxsize = int(kwargs.get('maxsize', 0))
    # https://www.freebsdchina.org/forum/viewtopic.php?t=54269
    accept_encoding = headers.get('Accept-Encoding', '') or headers.get('Bccept-Encoding', '')
    errors = []
    for i in xrange(int(kwargs.get('fetchmax', URLFETCH_MAX))):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, allow_truncated=False, follow_redirects=False, deadline=deadline, validate_certificate=validate_certificate)
            break
        except apiproxy_errors.OverQuotaError as e:
            time.sleep(5)
        except urlfetch.DeadlineExceededError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.DownloadError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.ResponseTooLargeError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            response = e.response
            logging.error('ResponseTooLargeError(deadline=%s, url=%r) response(%r)', deadline, url, response)
            m = re.search(r'=\s*(\d+)-', headers.get('Range') or headers.get('range') or '')
            if m is None:
                headers['Range'] = 'bytes=0-%d' % (maxsize or URLFETCH_MAXSIZE)
            else:
                headers.pop('Range', '')
                headers.pop('range', '')
                start = int(m.group(1))
                headers['Range'] = 'bytes=%s-%d' % (start, start+(maxsize or URLFETCH_MAXSIZE))
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.SSLCertificateError as e:
            errors.append('%r, should validate=0 ?' % e)
            logging.error('%r, deadline=%s', e, deadline)
        except Exception as e:
            errors.append(str(e))
            if i == 0 and method == 'GET':
                deadline = URLFETCH_TIMEOUT * 2
    else:
        start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Status', '502')])
        error_string = '<br />\n'.join(errors)
        if not error_string:
            logurl = 'https://appengine.google.com/logs?&app_id=%s' % os.environ['APPLICATION_ID']
            error_string = 'Internal Server Error. <p/>try <a href="javascript:window.location.reload(true);">refresh</a> or goto <a href="%s" target="_blank">appengine.google.com</a> for details' % logurl
        yield message_html('502 Urlfetch Error', 'Python Urlfetch Error: %r' % method, error_string)
        raise StopIteration

    status_code = int(response.status_code)
    data = response.content
    response_headers = response.headers
    content_type = response_headers.get('content-type', '')
    if status_code == 200 and maxsize and len(data) > maxsize and response_headers.get('accept-ranges', '').lower() == 'bytes' and int(response_headers.get('content-length', 0)):
        status_code = 206
        response_headers['Content-Range'] = 'bytes 0-%d/%d' % (maxsize-1, len(data))
        data = data[:maxsize]
    if status_code == 200 and 'content-encoding' not in response_headers and 512 < len(data) < URLFETCH_DEFLATE_MAXSIZE and content_type.startswith(('text/', 'application/json', 'application/javascript')):
        if 'gzip' in accept_encoding:
            response_headers['Content-Encoding'] = 'gzip'
            compressobj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
            dataio = io.BytesIO()
            dataio.write('\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff')
            dataio.write(compressobj.compress(data))
            dataio.write(compressobj.flush())
            dataio.write(struct.pack('<LL', zlib.crc32(data) & 0xFFFFFFFFL, len(data) & 0xFFFFFFFFL))
            data = dataio.getvalue()
        elif 'deflate' in accept_encoding:
            response_headers['Content-Encoding'] = 'deflate'
            data = deflate(data)
    response_headers['Content-Length'] = str(len(data))
    response_headers_data = deflate('\n'.join('%s:%s' % (k.title(), v) for k, v in response_headers.items() if not k.startswith('x-google-')))
    if 'rc4' not in options or content_type.startswith(('audio/', 'image/', 'video/')):
        start_response('200 OK', [('Content-Type', 'image/gif')])
        yield struct.pack('!hh', status_code, len(response_headers_data))+response_headers_data
        yield data
    else:
        start_response('200 OK', [('Content-Type', 'image/gif'), ('X-GOA-Options', 'rc4')])
        yield struct.pack('!hh', status_code, len(response_headers_data))
        yield RC4Cipher(__password__).encrypt(response_headers_data)
        yield RC4Cipher(__password__).encrypt(data)
