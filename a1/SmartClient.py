# CSC 361 Assignment 1 SmartClient.py
# Dillan Spencer V00914254

import socket
import sys
import ssl
import re

# GLOBAL VARIABLES
default_version = "HTTP/1.1"
crlf = "\r\n"
depth = 0

protocol_support = [False, False, False]
HTTP_1_1 = 0
HTTPS = 1
HTTP2 = 2


# Creates a socket for sending and receiving data from the server
# Params:
# server: server address eg. www.uvic.ca
# encrypt: boolean - wraps socket and changes port to 443
# Returns:
# socket connected to server on port 80 or 443
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


# Checks whether server supports HTTP 2.0
# If there is a socket error when connecting to port 443
# Params: # server: server address eg. www.uvic.ca
# Returns: support: (boolean) supports HTTP 2.0
def isHTTP2(server):
    context = getHttpContext()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=server)

    try:
        conn.connect((server, 443))
        protocol_support[HTTPS] = True
    except socket.error as err:
        print("Error connecting on port 443 with wrapped socket...", err)

    # Check if protocol is 'h2'
    support = (conn.selected_alpn_protocol() == 'h2')
    protocol_support[HTTP2] = support

    return support


# Creates ssl context with correct protocols for HTTP 2.0
# Returns: context: ssl context for HTTP 2.0 socket
def getHttpContext():
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.options |= (
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
    )

    context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])

    try:
        context.set_npn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    return context


# Parses through the response header and pulls out all cookie data
# Params: head: response header, domain: server address
# Returns: (list) list of cookie data
def findCookies(head, domain):
    pattern = re.compile("[Ss]et-[Cc]ookie: .+")
    pattern_key = re.compile("(\S+)(=\S*;)")
    pattern_domain = re.compile("([Dd]omain=)(\S+)")
    pattern_expires = re.compile("([Ee]xpires=)(\S+.\S+.\S+.\S+.)")

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

        # find domain name if any
        if pattern_expires.search(cookie) is not None:
            expires = pattern_expires.search(cookie).group(2)
        else:
            expires = None

        # format cookie properties into string for output
        if expires is not None:
            cookie_format = "Cookie: - Key: " + key + ", Domain Name: " + domain + ", Expires: " + expires
        else:
            cookie_format = "Cookie: - Key: " + key + ", Domain Name: " + domain

        # append cookie to list
        cookies.append(cookie_format)

    return cookies


# Parses through response header and finds redirect location
# Looks for https in header and decides weather server supports HTTPS
# Params: header: response header
# Returns: server: redirect address, (boolean) support: HTTPS support
def redirect(server, header):
    global depth
    depth += 1
    pattern = re.compile("([Ll]?ocation: http[s]?://)((www.\S+\.\w{2,3})(/)?(?!http[s]?://))")
    http_pattern = re.compile("https://")

    try:
        match = pattern.search(header).group()
    except AttributeError:
        return server, True, True

    server = pattern.search(match).group(3)

    if http_pattern.search(match) is not None:
        support = True
    else:
        support = False

    print(server, "Found in redirect")

    return server, support, False


# Builds a request str and sends it to the server using the socket
# Params:
# (socket) sock: socket used for sending request
# (str) server: server address
def request(sock, server):
    # create http request
    print("Initializing request...")

    req = "GET / HTTP/1.1\r\nHOST:{}\r\nCONNECTION:Keep-Alive\r\n\r\n".format(server)
    encoded_request = req.encode(errors='ignore')

    # Send http request
    print("Sending request to HTTP through socket")
    sock.sendall(encoded_request)
    print(req)


# Parses through response header and pulls out version and status code
# Params: data: response header
# Returns:
# http_version: newest version that the server supports
# status: status code (eg. 200)
def evaluateHead(data):
    version_pattern = re.compile("HTTP/\d\.\d")
    status_pattern = re.compile("\d{3}")

    http_version = version_pattern.match(data).group()
    status = status_pattern.search(data).group()

    return http_version, status


# Receives data from the server and handles data accordingly
# Params:
# (socket) sock: socket used for sending request
# (str) server: server address
def response(sock, server):
    support = None
    cookies = []
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

    # find http version and response code
    # -----------------------
    version, status = evaluateHead(data_head)

    # check for HTTP 1.1
    if version == default_version:
        protocol_support[HTTP_1_1] = True

    # Verify specifics based off of results
    # -----------------------
    if status == '200':
        support = True
        done = True

    elif status == '301':
        print("Status 301")
        server, support, done = redirect(server, data_head)

        if support:
            protocol_support[HTTPS] = True
            cookies = findCookies(data_head, server)
            return server, version, cookies, True, done

    elif status == '302':
        print("Status 302")
        server, support, done = redirect(server, data_head)

        if support:
            protocol_support[HTTPS] = True
            cookies = findCookies(data_head, server)
            return server, version, cookies, True, done

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

    print("Version: ", version)
    print("Status: ", status)
    # add support to support protocol list
    protocol_support[HTTP_1_1] = support

    # find list of cookies
    cookies = findCookies(data_head, server)

    return server, version, cookies, False, done


# Prints out all of the answers for support and cookies
# Params: cookies: list of cookie data
def deliverables(cookies):
    print("---------------------------------")
    print("DELIVERABLES: \n")
    # Support for HTTP 1.0
    print("Support HTTP/1.1: {}".format(protocol_support[HTTP_1_1]))

    # Support for HTTPS
    print("Support HTTPS: {}".format(protocol_support[HTTPS]))

    # Support for HTTP 2.0
    print("Support HTTP/2.0: {}".format(protocol_support[HTTP2]))

    # check if website doesnt use cookies
    if len(cookies) == 0:
        print("No Cookies Found...")

    # print list of cookies
    for cookie in cookies:
        print(cookie)


# MAIN
def main():
    print("Running Program...\n")

    # Grab domain name and initial variables
    domain = sys.argv[1]
    server = domain
    encrypt = False

    while True:
        sock = createSocket(server, encrypt)
        request(sock, server)
        server, version, cookies, encrypt, done = response(sock, server)
        sock.close()
        if done:
            break

    isHTTP2(server)

    deliverables(cookies)


if __name__ == '__main__':
    main()
