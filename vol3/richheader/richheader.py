# Rich Header
# Copyright (C) 2021 Kevin Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/volatility_plugins
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
import re
import hashlib
from binascii import hexlify
from typing import List

from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework import constants, exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class RichHeader(interfaces.plugins.PluginInterface):
    """Scans process memory for each process to identify CobaltStrike config"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]

    @classmethod
    def xor(self, data, key):
        """Multibyte XOR Decode"""
        l = len(key)
        return bytearray((
            (data[i] ^ key[i % l]) for i in range(0,len(data))
        ))


    @classmethod
    def parse_result(self, raw_data):
        """Search the bytes for the Rich Header, extract the XOR key and walk the strucutre
        return: XOR Key, md5sum of the decoded header
        """

        rich_header_pattern = b'DOS mode(.*?)Rich(....)'

        search = re.search(rich_header_pattern, raw_data, re.DOTALL)
        if search:
            xor_key = search.group(2)
            header = search.group(1)

            decoded_header = b''

            # We need to walk backwards until we find the decoded header
            for i in range(len(header), 0, -4):
                section = header[i:i+4]
                xor_section = self.xor(section, xor_key)
                decoded_header = xor_section + decoded_header
                vollog.debug(xor_section)
                if xor_section == b'DanS':
                    result = hashlib.md5(decoded_header)
                    return xor_key, result.hexdigest()
        else:
            return None, None


    def _generator(self):

        kernel = self.context.modules[self.config['kernel']]
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        for proc in pslist.PsList.list_processes(context = self.context,
                                                    layer_name = kernel.layer_name,
                                                    symbol_table = kernel.symbol_table_name,
                                                    filter_func = filter_func):
            
            try:
                process_name = utility.array_to_string(proc.ImageFileName)
                vollog.debug(f'Scanning Process {process_name}\n')
                proc_layer_name = proc.add_process_layer()
                peb = self.context.object(kernel.symbol_table_name + constants.BANG + "_PEB",
                                    layer_name = proc_layer_name,
                                    offset = proc.Peb)
                dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                            offset = peb.ImageBaseAddress,
                                            layer_name = proc_layer_name)

                for offset, data in dos_header.reconstruct():
                    xor_key, rich_header_hash = self.parse_result(data)
                    if rich_header_hash:
                        yield (0, (
                            proc.UniqueProcessId,
                            process_name,
                            hexlify(xor_key).decode(),
                            rich_header_hash,
                            ))
                        break

            except Exception as err:
                vollog.info(f'Unable to read proc for pid {proc.UniqueProcessId} {err}')

    def run(self):

        return renderers.TreeGrid([
                ("PID", int),
                ("Process", str),
                ("XOR Key", str),
                ("Rich Header Hash", str)
            ],
            self._generator(
                ))
