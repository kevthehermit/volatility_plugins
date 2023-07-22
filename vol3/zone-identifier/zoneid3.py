import contextlib
import logging
import re
from typing import List

from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins import yarascan

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise


class ZoneID3(interfaces.plugins.PluginInterface):
    """Scans for ZoneIdentifier 3 streams"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]
    

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_rules": "[ZoneTransfer]\\r\\nZoneId=3"}
        )

        # Scan the layer for Raw MFT records and parse the fields
        for offset, _rule_name, _name, _value in layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=rules)
            ):
            with contextlib.suppress(exceptions.PagedInvalidAddressException):
                # read 1024 bytes from the result to parse
                zone_data = layer.read(offset, 1024, False)

                host_url_match = re.search(b'HostUrl=(.*?)\r\n', zone_data)
                host_url = host_url_match.group(1) if host_url_match else b'NotPresent'

                referrer_url_match = re.search(b'ReferrerUrl=(.*?)\r\n', zone_data)
                referrer_url = referrer_url_match.group(1) if referrer_url_match else b'NotPresent'

                # Only return if we parsed at least one field
                if referrer_url == host_url == b'NotPresent':
                    continue
                else:
                    yield(0,(
                        "3",
                        host_url.decode(),
                        referrer_url.decode()
                    ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("ZoneID", str),
                ("Host URL", str),
                ("Referrer Url", str),
            ],
            self._generator(),
        )