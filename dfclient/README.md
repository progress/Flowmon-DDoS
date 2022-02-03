# Radware DefenseFlow integration script for Flowmon DDoS Defender

Version: 0.2

Date: January 9th 2019

These scripts allow you to add interface to Radware DefenseFlow appliance in order to inform it about detected DDoS attacks. Flowmon DDoS Defender must be at version 3.01.00 or higher for those scripts to work properly.

At this moment the script is only starting and stopping incident detection and it is expected that configuration of APSolute Vision and DefenseFlow is done already.

## Installation
1. Unpack the zip file and upload file *dfclient.pl* into */home/flowmon* directory using your favorite SCP/SFTP client.
2. Make file executable by running command `chmod a+x /home/flowmon/dfclient.pl`.
3. Modify in the file dfclient.pl using your favorite text editor lines 20 to 23. Your DefenseFlow credentials and IP belongs there.
4. Login to DDoS Defender.
5. Go to Configuration and there modify or create a new alert.
6. In the alert select option to Run Script and upload here file *dfmitigation.sh*. Also select option Run when attack is detected and attack characteristics are collected and Run when attack is ended. This will ensure that DefenseFlow is informed about attack start and stop.
7. Add this alert to the segment action where you wish to have DefenseFlow automatically instructed.
    
## Requirements
1. APSolute Vision 3.90.01 (build 718)
2. DefenseFlow 2.7.9
3. Workflow configuration on DefenseFlow (Security Settings)
4. Protected Objects (Security Settings)
    
## What's new & bugfixes
---------------------  
*Version 0.2*
- Added update of signature support which requires DDoS defender version 4.1 and higher
*Version 0.1*
- Initial release
