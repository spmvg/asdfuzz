import logging
import socket
import ssl
import time
import traceback
from dataclasses import dataclass

from asdfuzz.http.request import Request
from asdfuzz._utils import _get_header, _get_data

logger = logging.getLogger(__name__)


@dataclass
class Response:
    """ A single HTTP response. """
    response: bytes
    """ The raw response in bytes. """
    time: float
    """ The time in seconds that the response took. """

    def __post_init__(self):
        self.header: bytes = _get_header(self.response)
        self.data: bytes = _get_data(self.response)

    @property
    def statuscode(self):
        """ The HTTP statuscode of the response. """
        return int(self.response.splitlines()[0].split(b' ')[1])

    @classmethod
    def from_request(cls, request: Request) -> 'Response':
        """ Execute a request and return a ``Response``. """
        logger.debug('Creating default context')
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        response = b''

        t0 = time.time()
        logger.debug('Creating connection')
        with socket.create_connection((request.host, request.port)) as sock:
            sent_data = request.recreate()
            if not request.disable_https:
                logger.debug(f'Sending HTTPS request with data: {sent_data}')
                with context.wrap_socket(sock, server_hostname=request.host) as ssock:
                    ssock.sendall(sent_data)

                    logger.debug('Reading data from socket')
                    while True:
                        try:
                            data = ssock.recv()
                        except ssl.SSLError:
                            # TODO: make exception handling more specific - this can happen to more than just EOF
                            logger.warning(f'Encountered SSLError: {traceback.format_exc()}')
                            break
                        logger.debug(f'Received data: {data}')
                        if not data:
                            break
                        response += data
            else:
                logger.debug(f'Sending HTTP request with data: {sent_data}')
                sock.sendall(sent_data)

                logger.debug('Reading data from socket')
                while True:
                    data = sock.recv(4096)
                    logger.debug(f'Received data: {data}')
                    if not data:
                        break
                    response += data
        return Response(
            response=response,
            time=time.time()-t0,
        )
