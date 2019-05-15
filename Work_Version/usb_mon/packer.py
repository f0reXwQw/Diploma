# -*- coding: utf-8 -*-
import sys
import socket
import logging
import argparse
from server import send_message, read_message


logging.basicConfig(
    format='%(asctime)s [%(levelname)-5.5s]  %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    level=logging.INFO
)
logger = logging.getLogger(__name__)


if __name__ == '__main__':
    # parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-conn-str', type=str, default='127.0.0.1:45678', help='Connection string')
    parser.add_argument('--ssn', type=str, default='1', help='Software Serial Number; default is 1')
    args = parser.parse_args()

    # parse input arguments
    ip, port = args.conn_str.split(':')
    port = int(port)

    # check the given SSN
    try:
        s = socket.create_connection((ip, port))
        send_message(s, args.ssn)
        decryption_key = read_message(s)
        logger.info('Requested key with SSN %s: %s', args.ssn, decryption_key)

    except Exception as ex:
        logger.error('Requested key with SSN %s: %s', args.ssn, ex, exc_info=True)

    # check an invalid SSN
    ssn = '3462345e45y45656245763@$%'
    try:
        s = socket.create_connection((ip, port))
        send_message(s, ssn)
        decryption_key = read_message(s)
        logger.info('Requested key with SSN %s: %s', ssn, decryption_key)

    except Exception as ex:
        logger.error('Requested key with SSN %s: %s', ssn, ex, exc_info=True)
