# Author: Kevin Breen
# Thanks to the guide on http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.conf as conf
import re
import json

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


signatures = {
    'lastpass_struct_a' : 'rule lastpass_strcuta {strings: $a = /{"reqinfo":.*"lplanguage":""}/ condition: $a}\nrule lastpass_strcutb {strings: $a = /"tld":".*?","unencryptedUsername":".*?","realmmatch"/ condition: $a}'
}

config = conf.ConfObject()
config.add_option('CONFSIZE', short_option='C', default=2000,
                           help ='Config data size',
                           action ='store', type='int')
config.add_option('YARAOFFSET', short_option='Y', default=0,
                           help ='YARA start offset',
                           action ='store', type='int')

class LastPass(taskmods.PSList):
    """ Extract lastpass data from process. """

    def calculate(self):
        """ Required: Runs YARA search to find hits """
        if not has_yara:
            debug.error('Yara must be installed for this plugin')

        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources = signatures)
        for task in self.filter_tasks(tasks.pslist(addr_space)):
            if not task.ImageFileName.lower() in ['chrome.exe', 'firefox.exe', 'iexplore.exe']:
                continue
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():
                yield task, address

    def clean_json(self, raw_data):
        # We deliberatly pull in too much data to make sure we get it all.
        # Now parse it out again

        if raw_data.startswith("\"tld"):
            pattern = '"tld":".*?","unencryptedUsername":".*?","realmmatch"'
            val_type = 'username'
        else:
            pattern = '{"reqinfo":.*?"lplanguage":""}'
            val_type = 'password'

        match = re.search(pattern, raw_data)

        if val_type == 'username':
            vars = match.group(0).split(',')
            tld = vars[0].split(':')[1].strip('"')
            username = vars[1].split(':')[1].strip('"')
            return {'type': 'username', 'username': username, 'tld': tld}
        else:
            json_data = json.loads(match.group(0))
            tld = json_data['domains']
            password = json_data['value']
            return {'type': 'password', 'password': password, 'tld': tld}



    def render_text(self, outfd, data):
        """ Required: Parse data and display """
        outfd.write("LastPass Results")

        delim = '-=' * 39 + '-'
        rules = yara.compile(sources = signatures)

        results = {}

        for task, address in data:  # iterate the yield values from calculate()
            outfd.write('Checking Process: {0} ({1})\n'.format(task.ImageFileName, task.UniqueProcessId))
            proc_addr_space = task.get_process_address_space()
            raw_data = proc_addr_space.read(address + self._config.YARAOFFSET, self._config.CONFSIZE)
            clean_data = self.clean_json(raw_data)


            if clean_data['tld'] in results:
                if 'username' in clean_data:
                    results[clean_data['tld']]['username'] = clean_data['username']
                if 'password' in clean_data:
                    results[clean_data['tld']]['password'] = clean_data['password']
            else:
                if 'username' in clean_data:
                    username = clean_data['username']
                else:
                    username = 'Unknown'
                if 'password' in clean_data:
                    password = clean_data['password']
                else:
                    password = 'Unknown'

                results[clean_data['tld']] = {'username': username, 'password': password}

        #outfd.write('\n\n\n\n\n')

        for k, v in results.iteritems():
            outfd.write("\nFound LastPass Entry for {0}\n".format(k))
            outfd.write('UserName: {0}\n'.format(v['username']))
            outfd.write('Pasword: {0}\n'.format(v['password']))
            outfd.write('\n')
        outfd.write('\n')
