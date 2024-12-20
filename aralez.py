import re
import ssl

from argparse import ArgumentParser, FileType, Namespace, RawTextHelpFormatter
from base64 import b64decode
from datetime import datetime
from ipaddress import ip_address
from json import loads as json_decode, JSONDecodeError
from secrets import token_urlsafe
from typing import Callable, Iterable
from urllib.parse import quote
from wsgiref.simple_server import make_server


__version__ = 1


def http_serve(args: Namespace) -> None:
    """ Serve Aralez template over HTTPS

    """
    HTML_TEMPLATE: bytes = args.template.read()
    HTML_TEMPLATE_PATH: str = args.template.name
    BASIC_AUTH: str = args.auth

    def application(env: dict, start_response: Callable) -> Iterable:
        nonlocal HTML_TEMPLATE, HTML_TEMPLATE_PATH, BASIC_AUTH

        headers: list = [
            ('Content-Type', 'text/html'),
            ('Cache-Control', 'no-store'),
        ]
        response_status: str = ''
        response_body: bytes = b''

        try:
            if env['PATH_INFO'] != '/':
                response_status = '404 Not Found'
                response_body = b'<h1>404 Not Found</h1>'
            else:
                now = datetime.now()

                if BASIC_AUTH and not (
                    (credentials := env.get('HTTP_AUTHORIZATION'))
                    and b64decode(
                        credentials.split(' ', 1)[1].encode()
                    ).decode() == BASIC_AUTH.format(
                        today=now.day,
                        hour=now.hour
                    )
                ):
                    headers.append((
                        'WWW-Authenticate',
                        'Basic realm="private"'
                    ))

                    response_status = '401 Unauthorized'
                    response_body = b'<h1>401 Unauthorized</h1>'
                else:
                    match env['REQUEST_METHOD']:
                        case 'GET':
                            response_status = '200 OK'
                            response_body = HTML_TEMPLATE
                        case 'PUT':
                            response_status = '400 Bad Request'
                            response_body = b'<h1>400 Bad Request</h1>'

                            if (
                                env.get('CONTENT_TYPE') == 'application/json'
                                and (clen := env.get('CONTENT_LENGTH', ''))
                                and clen.isdecimal()
                            ):
                                body: bytes = env['wsgi.input'].read(int(clen))

                                try:
                                    secrets = json_decode(body)
                                    keys = frozenset((
                                        'title',
                                        'secret',
                                        'totpSecret',
                                        'totpHashAlgorithm',
                                    ))

                                    if not any(
                                        frozenset(secret) != keys
                                        for secret in secrets
                                    ):
                                        # replace data containing the secrets
                                        HTML_TEMPLATE = re.sub(
                                            rb'<data id="secrets"'
                                            rb' value="(.*)"></data>',

                                            '<data id="secrets"'
                                            f' value="{quote(body)}">'
                                            '</data>'.encode(),
                                            HTML_TEMPLATE
                                        )

                                        # save the modified template
                                        with open(
                                            HTML_TEMPLATE_PATH,
                                            'wb'
                                        ) as fd:
                                            fd.write(HTML_TEMPLATE)

                                        response_status = '200 OK'
                                        response_body = HTML_TEMPLATE
                                except JSONDecodeError:
                                    pass
                        case _:
                            response_status = '405 Method Not Allowed'
                            response_body = b'<h1>405 Method Not Allowed</h1>'
        except Exception as ex:
            print('[ERROR]', ex)
            response_status = '500 Internal Server Error'
            response_body = b'<h1>500 Internal Server Error</h1>'

        start_response(response_status, headers)
        return [response_body]

    # close descriptors to the opened files as only their paths are needed
    args.cert.close()
    args.key.close()
    args.template.close()

    # load TLS certificate and private key
    try:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.cert.name, args.key.name)
    except ssl.SSLError as serr:
        print(
            '[ERROR] Error occured while setting up HTTPS (',
            serr,
            '). Please check the certificate and key files',
            sep=''
        )
        return

    # enable S on HTTP server
    httpd = make_server(args.bind, args.port, application)
    httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)

    try:
        with httpd:
            print(
                'Serving HTTPS requests on https://',
                args.bind,
                ':',
                args.port,
                '...',
                sep=''
            )
            httpd.serve_forever()
    except KeyboardInterrupt:
        print('Manually terminated! Goody Bye...')


def migrate(args: Namespace) -> None:
    old = args.source.read().decode()
    new = args.destination.read().decode()

    args.source.close()
    args.destination.close()

    secrets_pattern = re.compile(r'<data id="secrets" value="(.*)"></data>')
    salt_pattern = re.compile(r'<data id="salt" value="(.*)"></data>')

    if not (secrets := secrets_pattern.search(old)):
        print(
            '[ERROR] secrets not found in the "',
            args.source.name,
            '" source file',
            sep=''
        )
        return

    if not (salt := salt_pattern.search(old)):
        print(
            '[ERROR] salt not found in the "',
            args.source.name,
            '" source file',
            sep=''
        )
        return

    with open(args.destination.name, 'wb') as fd:
        fd.write(
            salt_pattern.sub(
                salt.group(0),
                secrets_pattern.sub(secrets.group(0), new)
            ).encode()
        )

    print('[SUCCESS] Migration completed successfully!')


def salt(args: Namespace) -> None:
    print(token_urlsafe())


def ip(s: str) -> str:
    return str(ip_address(s))


def main() -> None:
    cmd_parser = ArgumentParser(description='Development tool for Aralez')
    cmd_parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='Aralez 0.{}'.format(__version__),
        help='show version'
    )

    subparsers = cmd_parser.add_subparsers(
        required=True,
        title='available commands',
        help='commands'
    )

    server_parser = subparsers.add_parser(
        'serve',
        formatter_class=RawTextHelpFormatter,
        help='serve Aralez over HTTPS',
        description="""Serve Aralez HTML file over HTTPS.

As the Web Crypto API requires secure context, valid certificate and key files
must be provided for running the HTTPS server. The following command can be
used for generating self-signed certificate and corresponding private key:

# openssl req -nodes -new -x509 -days 365 -keyout server.key -out server.cert

An optional (basic) authentication can be added for the requests, but it
doesn't gaurantees the security of the served content. Please use a proper
authentiocation schema on production deployment.
""",
    )
    server_parser.set_defaults(function=http_serve)
    server_parser.add_argument(
        'template',
        type=FileType('rb'),
        help='path to the Aralez template'
    )
    server_parser.add_argument(
        '-c',
        '--cert',
        type=FileType('rb'),
        required=True,
        help='path to the HTTPS certificate'
    )
    server_parser.add_argument(
        '-k',
        '--key',
        type=FileType('rb'),
        required=True,
        help='path to the HTTPS private key'
    )
    server_parser.add_argument(
        '-b',
        '--bind',
        type=ip,
        default='0.0.0.0',
        help='bind to address'
    )
    server_parser.add_argument(
        '-p',
        '--port',
        type=int,
        default=80,
        help='port of the web-server'
    )
    server_parser.add_argument(
        '-a',
        '--auth',
        default='',
        help='HTTP basic authentication credentials, ex. user:password'
    )

    migration_parser = subparsers.add_parser(
        'migrate',
        description=(
            'Migrate secrets and the salt from one Aralez HTML file to another'
        ),
        help='migrate secrets from one Aralez file to another'
    )
    migration_parser.set_defaults(function=migrate)
    migration_parser.add_argument(
        'source',
        type=FileType('rb'),
        help='source file'
    )
    migration_parser.add_argument(
        'destination',
        type=FileType('rb'),
        help='destination file'
    )

    salt_parser = subparsers.add_parser(
        'salt',
        help='generate salt for cryptographyc operations'
    )
    salt_parser.set_defaults(function=salt)

    cmd_args = cmd_parser.parse_args()
    cmd_args.function(cmd_args)


if __name__ == '__main__':
    main()
