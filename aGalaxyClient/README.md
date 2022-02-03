# A10 aGalaxy client for Flowmon DDoS Defender

Version: 2.8

Date: Aug 5, 2020

These scripts are to add interface to configure A10 aGalaxy management platform with needed information for DDoS attack mitigation Flowmon DDoS Defender must be at version 5.2.1 or higher for those scripts to work properly. 
Also, it needs Flowmon version 11 in order to work well with aGalaxy Image 3.2.2.

## Installation
1. Modify in the file ./etc/aGalaxyConfig.pl using your favorite text editor lines 10 to 12. Your A10 aGalaxy login credentials and IP belongs there.
2. Login to DDoS Defender.
3. Go to Configuration and there modify or create a new alert.
4. In the alert select option to Run Script and upload here file `aGalaxyMitigation.sh`. Also select option Run when attack is detected and attack characteristics are collected and Run when attack is ended. This will ensure that aGalaxy box is configured and configuration is removed once attack is over. It is possible if you want to have all preconfiguration made then run test of the script while passing parameter install. This will create initial configuration and Zone template. You can use custom template with configuration and pass it as parameter to script. In template, you can use Threshold values:
	- 2110201 TCP PPS
    - 2110202 UDP PPS
    - 2110203 443 PPS
    - 2110204 80 PPS
    - 2110205 53 PPS
    - 2110206 ICMP PPS
    - 2110207 General PPS
    - 2110101 TCP BPS
    - 2110102 UDP BPS
    - 2110103 443 BPS
    - 2110104 80 BPS
    - 2110105 53 BPS
    - 2110106 ICMP BPS
    - 2110107 General BPS
	
Those IDs must be followed by number from 000 to 999 which represents the percentage of baseline from Flowmon system for those parts you would like to use i.e. 2110201100 would mean that script will fill in 100% of TCP PPS baseline.

5. Add this alert to the segment action where you wish to have A10 automatically instructed. In this version, it's expected that A10 appliance will do redirection but this can be easily changed.

## What's new & bugfixes
**Version 2.8**
- Added support for dual-mode with A10 TPS mitigation script
- Modified for support of 5.2.1

**Version 2.7**
- Added IP check to verify if IP under attack is not created in some other segment.
- Modified installation and logout not to be tried when aGalaxy isn't reachable.

**Version 2.6**
- In situation when during attack stop it fails to connect to aGalaxy we create persistent record and
  attempt to stop in on next successful connection.

**Version 2.5**
- Removed 443, 80 and 53 baselines as they are removed in version 4.5 DDD
- Added option to send notification email based on configuration in UI about mitigation

**Version 2.4**
- Fixed situation when there was a signature without protocol or port detected

**Version 2.3**
- Added option for two concurrent instances to have one sleep
- Fixed default behavior of creating ports of other services and protocols
- For version 5 changed way to search in current zones

**Version 2.0**
- Added option to start notification or not
- Update of signature and zone is now also processed
- Packed client to simplify installation and log rotation

**Version 1.9**
- Fixed incorrect initialization
- Debug log enabled by default

**Version 1.8**
- Fixed incident start for default 53, 80 and 443 mitigations
- Fixed value replace in template as on aGalaxy names with underscores are used
- Added check if zone exist to prevent errors when mitigation is turned from multiple devices

**Version 1.5**
- Initial public release

## Requirements
It requires on Flowmon OS these additional packages for Python 3 (in the brackets are used in my package). This is for the portion which is using the DDoS API to send email without it this won't be needed.

- Cement CLI Application Framework for Python version 2.10.12 (cement-2.10.12-py3-none-any.whl)
- PySocks (python36-pysocks-1.6.8-7.el7.noarch.rpm)
- Requests (python36-requests-2.14.2-2.el7.noarch.rpm)
- Six (python36-six-1.14.0-2.el7.noarch.rpm)
- urllib3 (python36-urllib3-1.25.6-1.el7.noarch.rpm)
- idna (python36-idna-2.7-2.el7.noarch.rpm)
