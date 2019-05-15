# !/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import sys
import struct
import logging
import argparse
import socketserver
import binascii
from lic_file import LicenceFileData


LIC_FILE_DATA = None
USB_BUS_DEV = None

logging.basicConfig(
    format='%(asctime)s [%(levelname)-5.5s]  %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    level=logging.INFO
)
logger = logging.getLogger(__name__)


"""
    Communication utils
"""


class InputOverflowException(Exception):
    pass


class InputUnderflowException(Exception):
    pass


def to_bytes(s):
    if type(s) is bytes:
        return s
    elif type(s) is str:
        return s.encode()
    else:
        return str(s).encode()


def to_string(b):
    if type(b) is str:
        return b
    elif type(b) is bytes:
        return b.decode()
    else:
        return str(b)


def read_message(s):
    received_buffer = s.recv(4)
    if len(received_buffer) < 4:
        raise InputUnderflowException('Failed to receive data: the received length is less than 8 bytes long')
    to_receive = struct.unpack('<I', received_buffer[0:4])[0]
    received_buffer = b''
    while len(received_buffer) < to_receive:
        data = s.recv(to_receive - len(received_buffer))
        if len(data) == 0:
            raise InputUnderflowException('Failed to receive data: the pipe must have been broken')
        received_buffer += data
    return received_buffer


def send_message(s, message):
    message = binascii.unhexlify(message)
    message = to_bytes(message)
    send_buffer = struct.pack('<I', len(message)) + message
    s.sendall(send_buffer)


"""
    The server
"""


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class ServerHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, srv):
        socketserver.BaseRequestHandler.__init__(self, request, client_address, srv)

    def handle(self):
        logger.info('Accepted  connection from %s', self.client_address[0])
        try:
            # locate the license file and extract the data
            if LIC_FILE_DATA is None:
                raise NotImplementedError('USB drive raw data extraction is not implemented yet! :-(')

            else:
                lic_file = LIC_FILE_DATA

            # get the software serial number
            req_ssn = read_message(self.request)

            # if the requested SSN is valid for the located license key give the client the KEY
            if lic_file.check_software_sn(to_string(binascii.hexlify(req_ssn))):
                logger.debug('Client "%s" has requested a key with the valid SSN: %s', self.client_address[0], req_ssn)
                send_message(self.request, lic_file.decryption_key)

            else:
                logger.debug('Client "%s" has requested a key with an invalid SSN: %s', self.client_address[0], req_ssn)

            # aborting connection is not a good idea, but for the illustrative purposes is OK
            return

        except Exception as ex:
            logger.error('Exception occurred: "%s"', ex, exc_info=True)

        finally:
            logger.info('Processed connection from "%s"' % self.client_address[0])


if __name__ == '__main__':
    # parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=45678, help='Service\'s port; default is 45678')
    parser.add_argument('--lic-file', type=str, default=None,
                        help='Path to license file; if given the USB device search is not performed')
    parser.add_argument('--usb', type=str, default=None,
                        help='Identifier in the form "bus:dev" of a USB device to be used as the dongle')
    parser.add_argument('-v', action='store_true', help='Be verbose')
    args = parser.parse_args()

    # process the input settings
    if args.lic_file:
        if not os.path.exists(args.lic_file):
            raise ValueError('License file {0} is missing'.format(args.lic_file))
        LIC_FILE_DATA = LicenceFileData.load(args.lic_file)
    USB_BUS_DEV = args.usb
    assert LIC_FILE_DATA is not None or USB_BUS_DEV is not None

    # setup logging
    if args.v:
        logger.setLevel(logging.DEBUG)

    # start serving
    address = ('0.0.0.0', args.port)
    server = ThreadedTCPServer(address, ServerHandler)
    server.serve_forever()
