# Open vSwitch & Floodlight controller client for Flowmon DDoS Defender

Version: 1.0

Date: August 19th 2017

This script is to add interface to configure Open vSwitch (OVS) via Floodlight SDN controller with needed information for DDoS attack mitigation Flowmon DDoS Defender must be at version 3.01.00 or higher for those scripts to work properly.

# Installation
1. Upload file **OVS_Floodlight_Mitigation_1.0.pl** into _/home/flowmon_ directory using your favourite SCP/SFTP client.
2. Make file executable by running  command `chmod a+x /home/flowmon/OVS_Floodlight_Mitigation_1.0.pl`.
3. In the file OVS_Floodlight_Mitigation_1.0.pl modify line 39 by using your favourite text editor. Type IP and used port of the Floodlight there (Floodlight's default port is 8080).
4. Login to DDoS Defender.
5. Go to Configuration and there modify or create a new alert.
6. In the alert select option to Run Script and upload here file **OVS_Floodlight.sh**. Also select option Run when attack is detected and attack characteristics are collected and Run when attack is ended. This will ensure that OVS is configured and configuration is removed once attack is over.
6. Add this alert to the segment action where you wish to have OVS automatically instructed.
