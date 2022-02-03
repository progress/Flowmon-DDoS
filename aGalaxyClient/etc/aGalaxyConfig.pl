# !/usr/bin/perl
# This is only a configuration for A10 access
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>, Jiri Krejcir <jiri.krejcir@flowmon.com>
# Version: 2.8

package aGalaxyClient;
use strict;

# Username and password for the appliance
sub get_user { return "admin" };
sub get_password { return "a10" };
sub get_ip { return "192.168.46.18" };

# Delete incidents after attack from aGalaxy? 1 = yes, 0 = no
sub get_delete_incident { return 0 };

# Should this instance wait before applying config? 1 = yes, 0 = no
sub get_sleep { return 0 };

# Debug to logs? 1 = yes, 0 = no
sub get_debug { return 1 };

# Send email notifications?
sub get_notification { return 0 };

# Send email notifications to NOC?
sub get_noc_send { return 0 };
sub get_noc { return "security\@flowmon.com"};

# Dual mode? 1 = yes, 0 = no
sub get_mode { return 0};

1;
