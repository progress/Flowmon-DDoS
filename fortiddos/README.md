# FortiDDoS client for Flowmon DDoS Defender

Version: 1.0

Date: Aug 5, 2021

This scrript is to add interface to configure FortiDDoS platform with needed information for DDoS attack mitigation Flowmon DDoS Defender must be at version 5.2.1 or higher for those scripts to work properly.
## Usage
1. Upload the files to _/hotme/flowmon/_
2. Modify in the file _/home/flowmon/fortiddos/etc/FortiDDoSConfig.pl_ using your favorite text editor lines 10 to 12. Your FortiDDoS login credentials and IP belongs there.
3. Login to DDoS Defender.
4. Go to Configuration and there modify or create a new alert.
5. In the alert select option to Run Script and upload here file FortiDDoSMitigation.sh. Also select option Run when attack is detected and attack characteristics are collected and Run when attack is ended. This will ensure that FortiDDoS box is configured and configuration is removed once attack is over.
6. Add this alert to the segment action where you wish to have FortiDDoS automatically instructed.
