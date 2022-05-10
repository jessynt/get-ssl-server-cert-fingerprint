import ssl
import socket
import hashlib

host = 'www.google.com'
port = 443
sni = 'www.google.com'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
wrappedSocket = ctx.wrap_socket(sock, server_hostname=sni)


try:
    wrappedSocket.connect((host, port))
    der_cert = wrappedSocket.getpeercert(True)
    thumb_md5 = hashlib.md5(der_cert).hexdigest()
    thumb_sha1 = hashlib.sha1(der_cert).hexdigest()
    thumb_sha256 = hashlib.sha256(der_cert).hexdigest()
    print("MD5: " + thumb_md5)
    print("SHA1: " + thumb_sha1)
    print("SHA256: " + thumb_sha256)
except Exception as e:
    print(e)
