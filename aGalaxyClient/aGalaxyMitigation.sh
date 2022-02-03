#!/bin/bash

# Author: Jiri Knapek
# Description: This is script to command A10 aGalaxy device and give it
#              information about DDoS attack in order to stop it.

# --- MANDATORY PART ---
# parse alert data and store them to variables
. /usr/local/bin/iad_alert_functions
# --- END OF MANDATORY PART ---
echo `date` "INFO: Event detected, starting mitigation script." >> /data/components/agalaxyclient/log/iad.log
/data/components/agalaxyclient/scripts/aGalaxyClient.pl $IAD_JS0N_PARAMETERS_FILE $@
echo `date` "INFO: Mitigation script completed." >> /data/components/agalaxyclient/log/iad.log