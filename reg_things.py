#!/usr/bin/env python

# Tested on v2.5
# written based on https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/registry/shutdown.py

"""
Note: All of the information being queried may not be present
"""

import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
from volatility.renderers import TreeGrid
import volatility.timefmt as timefmt
import volatility.utils as utils

from datetime import datetime
import struct

class USBSTOR(common.AbstractWindowsCommand):
    "Parse USB Data from the Registry"


    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self.regapi = None

    def calculate(self):
        addr_space = utils.load_as(self._config)
        self.regapi = registryapi.RegistryApi(self._config)
        self.regapi.set_current("SYSTEM")
        self.regapi.reset_current()
        currentcs = self.regapi.reg_get_currentcontrolset()

        if currentcs == None:
            currentcs = "ControlSet001"

        # Get list of devices form USBSTOR

        # RESET the API
        self.regapi.reset_current()
        # Store teh results in a dict
        results = {}
        results['subkeys'] = []
        results['USB_DEVICES'] = []


        USB_PATH = '{0}\\Enum\\USB'.format(currentcs)
        usb_key = self.regapi.reg_get_key('SYSTEM', USB_PATH)
        USB_STOR_PATH = '{0}\\Enum\\USBSTOR'.format(currentcs)
        usb_stor_key = self.regapi.reg_get_key('SYSTEM', USB_STOR_PATH)


        if usb_stor_key == None:
            results['exists'] = False
        else:
            results['exists'] = True

        sub_keys = self.regapi.reg_get_all_subkeys('SYSTEM', USB_STOR_PATH, given_root=usb_stor_key)
        for k in sub_keys:
            # Theses are grouped by vender
            #debug.info("Vendor / Brand / Rev: {0}".format(str(k.Name)))

            disk, vendor, product, rev = str(k.Name).split('&')
            vendor = vendor.split('_', 1)[-1]
            product = product.split('_', 1)[-1]
            rev = rev.split('_', 1)[-1]

            results['subkeys'].append(str(k.Name))
            usb_devs = self.regapi.reg_get_all_subkeys('SYSTEM', k, given_root=k)
            for dev in usb_devs:
                # These are individual devices
                # This is what we use to map in to the USB_DEVICES


                usb_info_dict = {}

                #Serial Number
                usb_info_dict['Serial Number'] = str(dev.Name)
                usb_info_dict['Vendor'] = vendor
                usb_info_dict['Product'] = product
                usb_info_dict['Revision'] = rev


                # Get all the sub values
                values = self.regapi.reg_yield_values('SYSTEM', dev, given_root=dev)
                debug.info("Device Values")
                for val in values:
                    key_name = val[0]
                    key_data = val[1]
                    usb_info_dict[key_name] = key_data

                # Now get the Drive letters if we can


                # Get the last written key for each device

                serial_number = usb_info_dict['Serial Number']
                usb_subkeys = self.regapi.reg_get_all_subkeys('SYSTEM', USB_PATH, given_root=usb_key)
                for a in usb_subkeys:
                    subs = self.regapi.reg_get_all_subkeys('SYSTEM', a, given_root=a)
                    for s in subs:
                        if serial_number.split('&')[0] == s.Name:
                            usb_info_dict['Device Last Plugged In'] = s.LastWriteTime


                # Check if the current NTUSER.dat file contains the MountPoints2 entry
                # If yes user = this one else user = unknown



            results['USB_DEVICES'].append(usb_info_dict)






        # Return the results dict
        yield results


    '''
    def unified_output(self, data):
        return TreeGrid([("Date/Time (UTC)", str),
                            ("Type", str),
                            ("Summary", str),
                            ("Source", str),
                        ], self.generator(data)
                      )

    def generator(self, data):
        for result in data:
            yield (0, ['{0}'.format(result.get('timestamp') if result.get('timestamp') else result.get('key').LastWriteTime),
                        '{0}'.format(result.get('value') if not result.get('timestamp_type') else result.get('timestamp_type')),
                        ('' if result.get('timestamp') else '{0}'.format(result.get('value'))),
                        ('' if not result.get('hive') else '{0} | {1}\\{2}'.format(result.get('value_name'),
                                                                                    result.get('hive'),
                                                                                    ('' if not result.get('key') else self.regapi.reg_get_key_path(result.get('key')))
                                                                                )
                                            ),
                    ]
                )
    '''
    # Print to screen
    def render_text(self, outfd, data):
        outfd.write('Reading the USBSTOR Please Wait\n')
        for result in data:
            if not result['exists']:
                outfd.write('USBSTOR Not found in SYSTEM Hive\n')
            else:
                for usbdev in result['USB_DEVICES']:
                    outfd.write('Found USB Drive: \n')
                    for k, v in usbdev.iteritems():
                        outfd.write('{0}\t{1}\n'.format(k, v))


        outfd.write('\n')
