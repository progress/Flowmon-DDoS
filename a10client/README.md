# A10 TPS client for Flowmon DDoS Defender

Version: 3.5
Date: Aug 5th 2020

This scripts are able to configure A10 TPS appliance with needed information for DDoS attack mitigation
Flowmon DDoS Defender must be at version 5.2.1 or higher for those scripts to work properly.
Also, it need Flowmon version 11 in order to work well with TPS Image 3.2.2-P1.

## Usage
1. Modify in the file ./etc/a10config.pl using your favourite text editor lines 10 to 12. Your A10 login credentials and IP belongs there. Then you can decide if you want TPS to be a BGP injector or not by setting up *get_advertised*.
2. Login to DDoS Defender.
3. Go to Configuration and there modify or create a new alert.
4. In the alert select option to Run Script and upload here file *a10mitigation.sh.* Also select option Run when attack is detected and attack characteristics are collected and Run when attack is ended. This will ensure that A10 box is configured and configuration is removed once attack is over. It is possible if you want to have all preconfiguration made on A10 TPS then run test of the script while passing parameter install. This will create initial configuration and Zone template. You can use custom template with configuration and pass it as parameter to script. In template, you can use Threshold values:
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

Those IDs must be followed by number from 000 to 999 which represents the percentage of baseline
from Flowmon system for those parts you would like to use i.e. 2110201100 would mean
that script will fill in 100% of TCP PPS baseline

5. Add this alert to the segment action where you wish to have A10 automatically instructed. In this version, it's expected that A10 appliance will do redirection but this can be easily changed.
    
## What's new & bugfixes
**Version 3.5**
- Added support for DDoS Defender 5.2.1
- Now supporting dual mode with aGalaxy script

**Version 3.2**
- Added Zone Template functionality
- Modified mitigation setup
- Added configuration for deciding who shall be the BGP injector
- Supported TPS Image 3.2.2-P1

**Version 2.3**
- Added support for IPv6 DDoS zone configuration

**Version 2.2**
- The scrip now also performs logoff at the end and added a few more modification 
  
**Version 1.0**
- Initial release
- There are two versions of script. a10client.pl is generating dynamic signature based on detected attack. 
- The a10client_v1 is using standard template which is deployed during attack to appliance. 
