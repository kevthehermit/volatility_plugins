# LastPass

## Descriptions
Read browser memory space and attempt to recover any resident artefact's.

**IMPORTANT**

It is important to note that this process only works if a memory image was taken whilst the lastpass plugin
was running in active browser. And will only find credentials for domains that are active in a tab

## Authors:

 - Kevin Breen

## Usage:

```vol.py --plugins=plugindir --profile=Win7SP1x64 -f win7mem.img lastpass```

Example output:
```
localadmin@tech-server:~$ vol.py --plugins=/home/localadmin/github/volatility_plugins/lastpass --profile=Win7SP1x86 -f /home/localadmin/Desktop/lastpass-mem.vmem lastpass
Volatility Foundation Volatility Framework 2.5
LastPass ResultsChecking Process: chrome.exe (3400)
Checking Process: chrome.exe (3400)
Checking Process: chrome.exe (3400)
Checking Process: chrome.exe (3840)
Checking Process: chrome.exe (3840)
Checking Process: chrome.exe (3840)
Checking Process: chrome.exe (3912)
Checking Process: chrome.exe (3912)
Checking Process: chrome.exe (3912)
Checking Process: chrome.exe (3912)
Checking Process: chrome.exe (4092)
Checking Process: chrome.exe (4092)
Checking Process: chrome.exe (4092)
Checking Process: chrome.exe (2036)
Checking Process: chrome.exe (2036)

Found LastPass Entry for hackforums.net
UserName: peters.lastpass
Pasword: jRvTxxxxxxxxxOTcl

Found LastPass Entry for facebook.com
UserName: peters.lastpass@gmail.com
Pasword: Unknown

Found LastPass Entry for sainsburys.co.uk
UserName: peters.lastpass
Pasword: mt5xxxxxxxxxzBj

Found LastPass Entry for leakforums.net
UserName: peterslastpass
Pasword: rmH6xxxxxxxx9a2

Found LastPass Entry for facebook.com,facebook.com,messenger.com
UserName: Unknown
Pasword: O3xxxxxxxxG7hs

```



## ToDo
 - Extend to other password managers.
 - Display more information.
 - Unified Output.