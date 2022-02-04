#!/bin/bash


# --- MANDATORY PART ---
# parse alert data and store them to variables
. /usr/local/bin/iad_alert_functions
# --- END OF MANDATORY PART --- 
echo `date` "INFO: Event detected, starting mitigation script." >> /tmp/iad.log
/home/flowmon/ovsScript.pl $IAD_JS0N_PARAMETERS_FILE $@  
echo `date` "INFO: Mitigation script completed." >> /tmp/iad.log  
