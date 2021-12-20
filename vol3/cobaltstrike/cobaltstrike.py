import logging
import re
import struct
from typing import List

from volatility3.framework import constants, exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise


signatures = {
    'cs_config_start': """rule cobaltstrike_config
                                {
                                strings:
                                  $a = {2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C}
                                  $b = {69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B}
                                  //$c = {?? 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}
                                condition:
                                  any of them
                                }"""
}

# Config Struct from 
# https://blog.didierstevens.com/2021/11/21/update-1768-py-version-0-0-10/
# We incluide the full mapping even though we dont need it for reference
CONFIG_STRUCT = {
        0x0001: 'payload type',
        0x0002: 'port',
        0x0003: 'sleeptime',
        0x0004: 'maxgetsize', #
        0x0005: 'jitter',
        0x0006: 'maxdns',
        0x0007: 'publickey',
        0x0008: 'server,get-uri',
        0x0009: 'useragent',
        0x000a: 'post-uri',
        0x000b: 'Malleable_C2_Instructions', #
        0x000c: 'http_get_header',
        0x000d: 'http_post_header',
        0x000e: 'SpawnTo', #
        0x000f: 'pipename',
        0x0010: 'killdate_year', #
        0x0011: 'killdate_month', #
        0x0012: 'killdate_day', #
        0x0013: 'DNS_Idle', #
        0x0014: 'DNS_Sleep', #
        0x0015: 'SSH_HOST', #
        0x0016: 'SSH_PORT', #
        0x0017: 'SSH_USER-NAME', #
        0x0018: 'SSH_PASSWORD', #
        0x0019: 'SSH_PUBKEY', #
        0x001a: 'get-verb',
        0x001b: 'post-verb',
        0x001c: 'HttpPostChunk', #
        0x001d: 'spawnto_x86',
        0x001e: 'spawnto_x64',
        0x001f: 'CryptoScheme', #
        0x0020: 'proxy',
        0x0021: 'proxy_username',
        0x0022: 'proxy_password',
        0x0023: 'proxy_type',
        0x0024: 'deprecated', #
        0x0025: 'license-id',
        0x0026: 'bStageCleanup', #
        0x0027: 'bCFGCaution', #
        0x0028: 'killdate',
        0x0029: 'textSectionEnd', #
        0x002a: 'ObfuscateSectionsInfo', #
        0x002b: 'process-inject-start-rwx',
        0x002c: 'process-inject-use-rwx',
        0x002d: 'process-inject-min_alloc',
        0x002e: 'process-inject-transform-x86',
        0x002f: 'process-inject-transform-x64',
        0x0030: 'DEPRECATED_PROCINJ_ALLOWED',
        0x0031: 'BIND_HOST',
        0x0032: 'UsesCookies',
        0x0033: 'process-inject-execute',
        0x0034: 'process-inject-allocation-method',
        0x0035: 'process-inject-stub',
        0x0036: 'HostHeader',
        0x0037: 'EXIT_FUNK',
        0x0038: 'SSH_BANNER',
        0x0039: 'SMB_FRAME_HEADER',
        0x003a: 'TCP_FRAME_HEADER',
        0x003b: 'HEADERS_TO_REMOVE',
        0x003c: 'DNS_beacon',
        0x003d: 'DNS_A',
        0x003e: 'DNS_AAAA',
        0x003f: 'DNS_TXT',
        0x0040: 'DNS_metadata',
        0x0041: 'DNS_output',
        0x0042: 'DNS_resolver',
        0x0043: 'DNS_STRATEGY',
        0x0044: 'DNS_STRATEGY_ROTATE_SECONDS',
        0x0045: 'DNS_STRATEGY_FAIL_X',
        0x0046: 'DNS_STRATE-GY_FAIL_SEC-ONDS',
    }

class CobaltStrike(interfaces.plugins.PluginInterface):
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
            requirements.PluginRequirement(name = 'vadyarascan', plugin = vadyarascan.VadYaraScan, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]


    @classmethod
    def parse_result(self, rule, value):
        """Parse the config from the result"""

        # https://github.com/Te-k/cobaltstrike/blob/master/lib.py 
        # This helped me figure out how to walk the structs after XOR

        if value.startswith(b'././'):
            xor_key = 0x2e
        elif value.startswith(b'ihih'):
            xor_key = 105
        else:
            xor_key = None

        vollog.debug(f'Found XOR Key {xor_key}')
        if not xor_key:
            vollog.info("Unable to find config file")
            return None

        # XOR the raw values to get the config section
        data = bytearray([c ^ xor_key for c in value])

        vollog.debug(data)

        config = {}
        i = 0
        while i < len(data) - 8:
            if data[i] == 0 and data[i+1] == 0:
                break
            dec = struct.unpack(">HHH", data[i:i+6])
            if dec[0] == 1:
                v = struct.unpack(">H", data[i+6:i+8])[0]
                config["dns"] = ((v & 1) == 1)
                config["ssl"] = ((v & 8) == 8)
            else:
                if dec[0] in CONFIG_STRUCT.keys():
                    key = CONFIG_STRUCT[dec[0]]
                else:
                    vollog.debug("Unknown config command {}".format(dec[0]))
                    key = str(dec[0])
                if dec[1] == 1 and dec[2] == 2:
                    # Short
                    config[key] = struct.unpack(">H", data[i+6:i+8])[0]
                elif dec[1] == 2 and dec[2] == 4:
                    # Int
                    config[key] = struct.unpack(">I", data[i+6:i+10])[0]
                elif dec[1] == 3:
                    # Byte or string
                    v = data[i+6:i+6+dec[2]]
                    try:
                        config[key] = v.decode('utf-8').strip('\x00')
                    except UnicodeDecodeError:
                        config[key] = v
            # Add size + header
            i += dec[2] + 6

        vollog.debug(config)
        return config

    def _generator(self, procs):

        # Compile the list of rules
        rules = yara.compile(sources = signatures)

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            vollog.debug(f'Scanning Process {process_name}\n')

            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            layer = self.context.layers[proc_layer_name]

            # Run the yara scan with our collection of rules. The offset is the important part here. 
            for offset, rule_name, name, value in layer.scan(context = self.context,
                                                             scanner = yarascan.YaraScanner(rules = rules),
                                                             sections = vadyarascan.VadYaraScan.get_vad_maps(proc)):

                if rule_name == 'cobaltstrike_config':
                    # Read 1024 bytes from the layer at the offset and try to parse out some values. 
                    config = self.parse_result(rule_name, layer.read(offset, 3096, False))
                    yield (0, (
                        proc.UniqueProcessId,
                        process_name,
                        config.get('port', 0),
                        config.get('sleeptime', 0),
                        config.get('jitter', 0),
                        config.get('server,get-uri', ''),
                        config.get('post-uri', ''),
                        config.get('spawnto_x86', ''),
                        config.get('spawnto_x64', ''),
                        config.get('pipename', ''),
                        config.get('license-id', 0),
                        ))


    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([
                ("PID", int),
                ("Process", str),
                ("Port", int),
                ("Sleep", int),
                ("Jitter", int),
                ("Server", str),
                ("POST_PATH", str),
                ("x86 Install_Path", str),
                ("x64 Install_Path", str),
                ('Pipe', str),
                ("License ID", int),
            ],
            self._generator(
                pslist.PsList.list_processes(context = self.context,
                                             layer_name = kernel.layer_name,
                                             symbol_table = kernel.symbol_table_name,
                                             filter_func = filter_func)))
