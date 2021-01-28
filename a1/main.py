import socket
import sys
import ssl
import time
import re

default_version = "HTTP/1.1"
crlf = "\r\n"

protocol_support = [False, False, False]
HTTP_1_1 = 0
HTTPS = 1
HTTP2 = 2


def createSocket(server, encrypt):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        port = 80

        if encrypt:
            print("Wrapping socket...")
            port = 443
            sock = ssl.wrap_socket(sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE,
                                   ssl_version=ssl.PROTOCOL_SSLv23)

        print("Creating connection with", server, "at port", port)
        sock.connect((server, port))

        return sock

    except socket.error as error:
        print("There was an error creating the socket! Error: ", error)
        sys.exit(1)


def isHTTPs(server, version):
    print("Checking if supports HTTPs...")
    sock = createSocket(server, True)
    request(sock, server, version)

    version, support, done = response(sock, server, version, True)

    # add support to support list
    protocol_support[HTTPS] = support

    return version, support, done


def isHTTP2(server, version):
    context = get_Http_Context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=server)

    try:
        if conn.connect((server, 443)) != socket.error:
            protocol_support[HTTPS] = True
    except socket.error:
        protocol_support[HTTPS] = False
    except ssl.SSLCertVerificationError as ssl_error:
        print("Certification failed")

    # Check if protocol is 'h2'
    support = (conn.selected_alpn_protocol() == 'h2')
    protocol_support[HTTP2] = support

    return support


# Find cookies
def findCookies(head, domain):
    pattern = re.compile("[Ss]et-Cookie: .+")
    pattern_key = re.compile("(\S+)(=\S*;)")
    pattern_domain = re.compile("([Dd]omain=)(\S+)")

    cookie_list = pattern.findall(head)
    cookies = []

    for cookie in cookie_list:
        # find keys if any
        if pattern_key.search(cookie) is not None:
            key = pattern_key.search(cookie).group(1)
        else:
            key = '-'

        # find domain name if any
        if pattern_domain.search(cookie) is not None:
            domain = pattern_domain.search(cookie).group(2)

        # format cookie properties into string for output
        cookie_format = "Cookie: - Key: " + key + ", Domain Name: " + domain

        # append cookie to list
        cookies.append(cookie_format)

    return cookies


def redirect(header):
    pattern = re.compile("(Location: http[s]?://)((www.\S+\.\w{2,3})(/)?(?!http[s]?://))")
    http_pattern = re.compile("https://")
    match = pattern.search(header).group()

    server = pattern.search(match).group(3)

    if http_pattern.search(match) is not None:
        support = True
    else:
        support = False

    print(server, "Found in redirect")

    return server, support


def request(sock, server, version):
    # create http request
    print("Initializing request...")

    req = "GET / HTTP/1.1\r\nHOST:{}\r\nCONNECTION:Keep-Alive\r\n\r\n".format(server)
    encoded_request = req.encode(errors='ignore')

    # Send http request
    print("Sending request to HTTP through socket")
    sock.sendall(encoded_request)
    print(req)


def HTTP2Request(sock, server, version):
    # create request
    print("Generating request...")
    request_line = "HEAD / " + version + " " + crlf
    general_header = "Connection: Upgrade, HTTP2-Settings" + crlf
    request_header = "Host: " + server + crlf + "Upgrade: h2c" + crlf + "HTTP2-Settings: " + crlf + "User-Agent: curl/7.35.0" + crlf + crlf

    req = request_line + general_header + request_header
    encoded_request = req.encode()

    print("Sending Request to HTTP 2.0")
    sock.sendall(encoded_request)
    print(req)


def evaluateHead(data):
    version_pattern = re.compile("HTTP/\d\.\d")
    status_pattern = re.compile("\d{3}")

    http_version = version_pattern.match(data).group()
    status = status_pattern.search(data).group()

    return http_version, status


def response(sock, server, version):
    support = None
    cookies = []
    domain = server
    print("Awaiting response from host...")

    # receive data
    data = sock.recv(4096)
    data_encoded = data.decode("latin1", errors='ignore')

    if data_encoded == '' or data_encoded is None:
        print("No data has been received.")
        sys.exit(1)

    print("Received data!")
    data_list = data_encoded.split(crlf + crlf)
    data_head = data_list[0]
    print("\n", data_head)

    if len(data_list) > 2:
        data_body = data_list[1]
    else:
        data_body = "Null"

    # find http version and response code
    # -----------------------
    version, status = evaluateHead(data_head)

    # Verify specifics based off of results
    # -----------------------
    if status == '200':
        support = True
        done = True

    elif status == '301':
        print("Status 301")
        server, support = redirect(data_head)
        cookies = findCookies(data_head, server)
        done = False

        if support:
            protocol_support[HTTPS] = True
            return server, version, cookies, True, False

    elif status == '302':
        print("Status 302")
        server, support = redirect(data_head)
        cookies = findCookies(data_head, server)
        print("\nRedirecting to: ", server, "\n")
        return server, default_version, cookies, True, False

    elif status == '400':
        print("status 400")
        done = True

    elif status == '404':
        print("Status 404 Bad request")
        done = True

    elif status == '408':
        print("Status 408")
        sys.exit()

    elif status == '505':
        print("Status 505")
        return server, "HTTP/1.0", cookies, False, False

    else:
        print("Unrecognized status code: exiting...")
        sys.exit(1)

    # print response head and body

    #  find cookies

    print("Version: ", version)
    print("Status: ", status)
    # add support to support protocol list
    protocol_support[HTTP_1_1] = support

    # find list of cookies
    cookies = findCookies(data_head, server)

    return server, version, cookies, False, done


def get_Http_Context():
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.options |= (
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
    )

    context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])

    try:
        context.set_npn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    return context


def HTTP2Response(sock, server):
    print("Awaiting response...")

    # Receive response
    data = sock.recv(4096)
    data_decoded = data.decode("latin1")

    version, status = evaluateHead(data_decoded)

    if version == 'HTTP/2.0' or status == '101':
        print("Http 2.0 is supported")
        return True

    # 302 error

    else:
        return False


def deliverables(cookies):
    print("---------------------------------")
    # Support for HTTP 1.0
    print("Support HTTP/1.1: ", protocol_support[HTTP_1_1])

    # Support for HTTPS
    print("Support HTTPS: ", protocol_support[HTTPS])

    # Support for HTTP 2.0
    print("Support HTTP/2.0: ", protocol_support[HTTP2])

    # check if website doesnt use cookies
    if len(cookies) == 0:
        print("Website has no Cookies...")

    # print list of cookies
    for cookie in cookies:
        print(cookie)


# MAIN
def main():
    print("Running Program...\n")

    # Grab domain name and initial variables
    domain = sys.argv[1]
    server = domain
    version = default_version
    cookies = []
    encrypt = False

    while True:
        sock = createSocket(server, encrypt)
        request(sock, server, version)
        server, version, cookies, encrypt, done = response(sock, server, version)
        sock.close()
        if done:
            break

    isHTTP2(server, version)

    deliverables(cookies)


if __name__ == '__main__':
    main()
