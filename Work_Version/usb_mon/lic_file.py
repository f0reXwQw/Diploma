# -*- coding: utf-8 -*-
import os
import json
import argparse
from usb_info import UsbDriveInfo


class LicenceFileData(object):
    DEFAULT_SSN = '1'
    LIC_FILE_NAME = 'protect.lic'

    def __init__(self):
        self.usb_info = UsbDriveInfo()
        self.software_sn = LicenceFileData.DEFAULT_SSN
        self.decryption_key = None

    def save(self, file_path):
        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, LicenceFileData.LIC_FILE_NAME)

        data = {
            'UsbDriveInfo': self.usb_info.to_dict() if self.usb_info else {},
            'SSN': self.software_sn,
            'KEY': self.decryption_key
        }
        with open(file_path, 'wb+') as f:
            f.write(json.dumps(data, indent=4).encode())

    @classmethod
    def load(cls, file_path):
        r = cls()
        with open(file_path, 'rb') as f:
            data = json.loads(f.read().decode())
            r.usb_info = UsbDriveInfo.from_dict(data.get('UsbDriveInfo'))
            r.software_sn = data.get('SSN')
            r.decryption_key = data.get('KEY')
        return r

    def check_lic_file(self, usb_info):
        if usb_info.vendor_id is None and usb_info.product_id is None and usb_info.serial_number is None:
            raise ValueError('Some identification info is required')

        # check the identification numbers, None value in the licence file is interpreted as the wildcard
        # check the VendorID
        if self.usb_info.vendor_id is not None and usb_info.vendor_id is not None:
            if self.usb_info.vendor_id != usb_info.vendor_id:
                return False

        # check the ProductID
        if self.usb_info.product_id is not None and usb_info.product_id is not None:
            if self.usb_info.product_id != usb_info.product_id:
                return False

        # check the Serial Number
        # TODO: encrypt the raw USB drive's Serial Number (possibly using an asymmetric encryption like RSA)
        if self.usb_info.serial_number is not None and usb_info.serial_number is not None:
            if self.usb_info.serial_number != usb_info.serial_number:
                return False

        # since all the checks were successful, the license key is valid fot the given device
        return True

    def check_software_sn(self, software_sn):
        # check the software number, '1' value in the licence file is interpreted as the wildcard
        return self.software_sn == software_sn


if __name__ == '__main__':
    # parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', type=str, default='.', help='License file path')
    parser.add_argument('--usb-name', type=str, default=None,
                        help='Device name of the USB to be used as the dongle; '
                             'if not given the license file will be valid for any USB device')
    parser.add_argument('--usb', type=str, default=None,
                        help='Identifier in the form "bus:dev" of USB to be used as the dongle; '
                             'if not given the license file will be valid for any USB device')
    parser.add_argument('--ssn', type=str, default='1', help='Software Serial Number; default is 1')
    parser.add_argument('--key', type=str, default='1D5FAD6C7645BBE4BC2A0E7E56B72F60',
                        help='Decryption key; default is AES-128 1D5FAD6C7645BBE4BC2A0E7E56B72F60')
    args = parser.parse_args()

    # create the license key
    lic = LicenceFileData()

    # set the hardware-related serial numbers (if required)
    # TODO: encrypt the raw USB drive's Serial Number (possibly using an asymmetric encryption like RSA)
    if args.usb is not None:
        bus_num, device_num = map(lambda x: int(x, 16), args.usb.split(':'))
        lic.usb_info = UsbDriveInfo.from_bus_device(bus_num, device_num)

    elif args.usb_name is not None:
        lic.usb_info = UsbDriveInfo.from_name(args.usb_name)

    # set the software serial number so that the license key only protects a particular software instance
    lic.software_sn = args.ssn

    # set the code decryption key
    lic.decryption_key = args.key

    # save the license file
    # TODO: encrypt contents of the license key file (possibly using an asymmetric encryption like RSA)
    lic.save(args.output)
