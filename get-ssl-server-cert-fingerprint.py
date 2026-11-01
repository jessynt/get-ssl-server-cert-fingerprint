import hashlib
import socket
import ssl
import sys

host = 'www.qq.com'
port = 443
sni = 'www.qq.com'
timeout = 5.0


def get_server_certificate(host, port, sni, timeout):
    if not 1 <= port <= 65535:
        raise ValueError('port 必须在 1 到 65535 之间')
    if timeout <= 0:
        raise ValueError('timeout 必须大于 0')

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=sni) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)

    if not der_cert:
        raise ssl.SSLError('服务器未提供证书')
    return der_cert


def main():
    try:
        der_cert = get_server_certificate(host, port, sni, timeout)
        fingerprints = [
            (algorithm.upper(), hashlib.new(algorithm, der_cert).digest())
            for algorithm in ('md5', 'sha1', 'sha256')
        ]
    except socket.timeout:
        print(f'连接或 TLS 握手超时（{timeout} 秒）', file=sys.stderr)
        return 1
    except (OSError, ValueError, OverflowError) as error:
        print(f'获取证书指纹失败: {error}', file=sys.stderr)
        return 1

    for algorithm, fingerprint in fingerprints:
        value = fingerprint.hex(':') if algorithm == 'SHA256' else fingerprint.hex()
        print(f'{algorithm}: {value}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
