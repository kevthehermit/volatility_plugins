import logging
import re
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

browser_procs = ['chrome.exe', 'firefox.exe', 'iexplore.exe']

signatures = {
    'lastpass_struct_a': 'rule lastpass_strcuta {strings: $a = /{"reqinfo":.*"lplanguage":""}/ condition: $a}\n'
                         'rule lastpass_strcutb {strings: $a = /"tld":".*?","unencryptedUsername":".*?","realmmatch"/ condition: $a}\n'
                         'rule lastpass_strcutc {strings: $a = /{"cmd":"save"(.*?)"tld":"(.*?)"}/ condition: $a}\n'
                         'rule lastpass_strcutd {strings: $a = /"realurl":"(.*?)"domains":"(.*?)"/ condition: $a}\n'
                         'rule lastpass_strcute {strings: $a = /{"cmd":"save"(.*?)"formdata"(.*?)}/ condition: $a}\n'
                         'rule lastpass_priv1 {strings: $a = /LastPassPrivateKey<(.*?)>LastPassPrivateKey/ condition: $a}'
}

class PasswordManager(interfaces.plugins.PluginInterface):
    """Scan all processs for browsers and then scan the process memory for any password manager fragments"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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
        """Takes a rule name and the raw data from the process and attempts to extract 3 values"""
        vollog.debug(rule)
        username = password = domain = None

        if rule.startswith('lastpass'):

            # RE Patterns for LastPass
            password_pattern = b'"logonPassword","value":"(.*?)"|"password","value":"(.*?)"'
            username_pattern = b'"unencryptedUsername":"(.*?)"'
            domain_pattern = b'"tld":"(.*?)"|"topurl":"(.*?)"'

        # Find all password elements and read first non empty field
        password_search = re.findall(password_pattern, value)
        try:
            password = next(item for item in password_search[0] if item != b'')
        except:
            password = b'Not found'

        # Find all username elements and read first non empty field
        username_search = re.findall(username_pattern, value)
        try:
            username = next(item for item in username_search if item != b'')
        except:
            username = b'Not found'

        # Find all domain elements and read first non empty field
        domain_search = re.findall(domain_pattern, value)
        try:
            domain = next(item for item in domain_search[0] if item != b'')
        except:
            domain = b'Not found'

        vollog.debug(f'\n\n------->{[username, password, domain]}\n\n')

        # From bytes to ascii as the GridTree will print hex otherwise
        return username.decode(), password.decode(), domain.decode()


    def _generator(self, procs):

        # Compile the list of rules
        rules = yara.compile(sources = signatures)

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            # continue to next loop if we are not in a supported browser process. 
            if not process_name in browser_procs:
                continue

            vollog.debug(f'Found Browser Process {process_name}\n')

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

                # Read 1024 bytes from the layer at the offset and try to parse out some values. 
                username, password, domain = self.parse_result(rule_name, layer.read(offset, 1024, False))

                # Only Yield if we have at least one value
                if username == password == domain == 'Not found':
                    pass
                else:
                    yield (0, (proc.UniqueProcessId, process_name, username, password, domain))

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Username", str), ("Password", str), ("Domain", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = kernel.layer_name,
                                                                   symbol_table = kernel.symbol_table_name,
                                                                   filter_func = filter_func)))
