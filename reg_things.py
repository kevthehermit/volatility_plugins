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

class RegThings(common.AbstractWindowsCommand):
    "Print some things from a registry"

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

        USB_STOR_PATH = '{0}\\Enum\\USBSTOR'.format(currentcs)
        key = self.regapi.reg_get_key('SYSTEM', USB_STOR_PATH)

        if key == None:
            results['exists'] = False
        else:
            results['exists'] = True

        sub_keys = self.regapi.reg_get_all_subkeys('SYSTEM', USB_STOR_PATH, given_root=key)
        for k in sub_keys:
            results['subkeys'].append(str(k.Name))




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
                for k in result['subkeys']:
                    outfd.write('Found USB Drive: ')
                    outfd.write(k)


        outfd.write('\n')

