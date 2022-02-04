# F5 client for Flowmon DDoS Defender

Version: 3.0

Date: April 24th 2017

This script is able to configure F5 appliance with needed information for DDoS attack mitigation Flowmon DDoS Defender must be at version 3.01.00 or higher for those scripts to work properly.
It is tested with BIG-IP version 12 and 13.

## Installation

1. Copy file **f5client.pl** into _/home/flowmon_ directory using your favourite SCP/SFTP client.
2. Make file executable by running  command `chmod a+x /home/flowmon/f5client.pl`.
3. Modify in the file f5client.pl using your favourite text editor lines 15 to 17. Your F5 login credentials and IP belongs there.
4. Login to DDoS Defender.
5. Go to Configuration and there modify or create a new alert.
6. In the alert select option to Run Script and upload here file **f5mitigation.sh**. Also select option Run when attack is detected and attack characteristics are collected and Run when attack is ended. This will ensure that F5 box is configured and configuration is removed once attack is over. If you wish to use a template of dos profile which is existing on F5, add it's name to script parametre.
6. Add this aler to the segment action where you wish to have F5 autmatically instructed. Don't forget, that you will need to redirect the traffic to F5.
    
## What's new & bugfixes
**Version 3.0**
- Fixed support for IPv6 segments
- modified DoS profile configuration to enable using Bad Actor and IP Intelligence

**Version 2.1**
- Initial release
- Support templates and utilizes iControllREST API for configuration of F5 appliance
