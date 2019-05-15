# -*- coding: utf-8 -*-
import pyudev


# TODO: implement USB drive raw data read/write


class UsbDriveInfo(object):
    def __init__(self):
        self.vendor_id = None
        self.product_id = None
        self.serial_number = None

    def to_dict(self):
        data = {
            'VendorID': self.vendor_id,
            'ProductID': self.product_id,
            'SN': self.serial_number
        }
        return data

    @classmethod
    def from_dict(cls, d):
        d = d or {}
        c = cls()
        c.vendor_id = d.get('VendorID')
        c.product_id = d.get('ProductID')
        c.serial_number = d.get('SN')
        return c

    @classmethod
    def from_name(cls, usb_name):
        ctx = pyudev.Context()
        for d in ctx.list_devices(subsystem='usb'):
            p = dict(d.properties)
            if p['DEVTYPE'] == 'usb_device':
                if usb_name in p['ID_SERIAL'] or usb_name in p['ID_VENDOR_FROM_DATABASE']:
                    c = cls()
                    c.vendor_id = int(p['ID_VENDOR_ID'], 16)
                    c.product_id = int(p['ID_MODEL_ID'], 16)
                    c.serial_number = p['ID_SERIAL_SHORT']
                    return c
        return None

    @classmethod
    def from_bus_device(cls, bus_num, device_num):
        ctx = pyudev.Context()
        for d in ctx.list_devices(subsystem='usb'):
            p = dict(d.properties)
            if p['DEVTYPE'] == 'usb_device':
                if int(p['BUSNUM'], 16) == bus_num and int(p['DEVNUM'], 16) == device_num:
                    c = cls()
                    c.vendor_id = int(p['ID_VENDOR_ID'], 16)
                    c.product_id = int(p['ID_MODEL_ID'], 16)
                    c.serial_number = p['ID_SERIAL_SHORT']
                    return c
        return None
