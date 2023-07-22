# volatility_plugins
A collection of plugins for the Volatility Memory Framework

Please see individual folders for details. 

## Vol3

### Cobalt Strike
Scans process memory for each process to identify CobaltStrike config and prints the config elements

### Password Managers
Extracts cached passwords from browser process memory. 
Supports:
- Lastpass

### Rich Header

Copied from the origional location for reference. 

Prints the XR Key and Rich Header Hash for all process executables. 

## Vol2

These plugins are no longer activly maintained and will be / have been ported to Volatilty V3

### USBSTOR
Parses the USBSTOR and other registry values from memory to identify USB Devices connected to the system

### LastPass
Read browser memory space and attempt to recover any resident artefacts

