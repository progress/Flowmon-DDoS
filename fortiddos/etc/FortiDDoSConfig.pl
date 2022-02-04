# !/usr/bin/perl
# This is only a configuration for FortiDDoS access
# Author:  Jiri Knapek <jiri.knapek@progress.com>
# Version: 1.0

package FortiDDoSClient;
use strict;

# Username and password for the appliance
sub get_user { return "flowmon" };
sub get_password { return "flowmon" };
sub get_ip { return "192.168.47.25" };

# Debug to logs? 1 = yes, 0 = no
sub get_debug { return 1 };

1;
