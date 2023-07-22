# volatility_plugins
A collection of plugins for the Volatility Memory Framework

Please see individual folders for details. 

## Vol3

### ZoneID3
Scans memory for ZoneIdentifier 3 ADS streams assocaited with files downloaded from the internet

```
$ vol -r pretty -p ~/github/volatility_plugins -f Win10Dev-Snapshot1.vmem zoneid3
Volatility 3 Framework 2.5.0
Formatting...0.00               PDB scanning finished
  | ZoneID |                                                                             Host URL |                                            Referrer Url
* |      3 |                                   https://download.sysinternals.com/files/Sysmon.zip | https://learn.microsoft.com/
* |      3 | https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml | NotPresent
* |      3 |                  https://download.splunk.com/products/universalforwarder/release.msi | NotPresent
* |      3 |                                           https://mh-nexus.de/downloads/HxDSetup.zip | https://mh-nexus.de/en/downloads.php?product=HxD20
* |      3 |                                                                           NotPresent | C:\Users\User\Downloads\PE-bear_0.6.1_x64_win_vs13.zip
```

### Cobalt Strike
Scans process memory for each process to identify CobaltStrike config and prints the config elements

```
❯ vol  -r pretty -p ~/github/volatility_plugins -f Server16-CobaltStrike.raw cobaltstrike
Volatility 3 Framework 2.5.0
Formatting...0.00               PDB scanning finished                        
  |  PID |        Process | Port | Sleep | Jitter |            Server |   POST_PATH |               x86 Install_Path |                x64 Install_Path |                Pipe | License ID
* | 4396 | ShellExperienc | 4444 | 10000 |      0 |                   |             | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe | \\.\pipe\msagent_89 | 1234567890
* | 4396 | ShellExperienc | 4444 | 10000 |      0 |                   |             | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe | \\.\pipe\msagent_89 | 1234567890
* | 4604 |   rundll32.exe |  443 |  5000 |      0 | 54.170.175.43,/ca | /submit.php | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe |                     | 1234567890
```

### Password Managers
Extracts cached passwords from browser process memory. 
Supports:
- Lastpass

```
$ vol -p ~/github/volatility_plugins -f Win7-Analysis-1d23dece.vmem passwordmanager 
Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished                                                                                              
PID     Process Username        Password        Domain

3400    chrome.exe      Not found       mt5JwaPvLctWFzBj        https://www.demodomain.co.uk/
3400    chrome.exe      Not found       Not found       https://leakforums.net/
3400    chrome.exe      Not found       rmH61LVBqHSVJ9a2        https://leakforums.net/
3400    chrome.exe      Not found       Not found       https://leakforums.net/
```

### Rich Header

Prints the XOR Key and Rich Header Hash for all process executables. 

```
$ vol -p ~/github/volatility_plugins -f Server16-CobaltStrike.raw richheader
Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished                        
PID     Process XOR Key Rich Header Hash

380     smss.exe        e8fbb614        b4da76d938693e03d2d455ef37561772
512     csrss.exe       fba319c1        e4971216867bfffb7beb058dca378a84
592     csrss.exe       fba319c1        e4971216867bfffb7beb058dca378a84
608     wininit.exe     75318913        f8116f1336d2c70bd16b01ad8be7bb6d
644     winlogon.exe    4bc258ac        c4f0d2eedff3968a8af33cf724e22790
716     services.exe    b05eb20c        75daeb432ccb73aa5349c09bd00c2945
728     lsass.exe       631ad1fb        5a2611fd92fa692a9663952ec838d57b
800     svchost.exe     fdedd411        bdf4caf91c4d0776c4021998c204944a
852     svchost.exe     fdedd411        bdf4caf91c4d0776c4021998c204944a

```

## Vol2

These plugins are no longer activly maintained and will be / have been ported to Volatilty V3

### USBSTOR
Parses the USBSTOR and other registry values from memory to identify USB Devices connected to the system

### LastPass
Read browser memory space and attempt to recover any resident artefacts

