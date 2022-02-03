#!/usr/bin/perl
# This is only a configuration for A10 access
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>, Jiri Krejcir <jiri.krejcir@flowmon.com>
# Version: 3.5

package a10TPSclient;
use strict;

# Username and password for the appliance
sub get_user { return "admin" };
sub get_password { return "a10" };
sub get_ip { return "192.168.46.15" };

# Configuration for A10 to propagate zone IPs 0 = disabled, 1 = enabled
sub get_advertised { return 0 };

# Debug to logs? 1 = yes, 0 = no
sub get_debug { return 1 };

# Dual mode? 1 = yes, 0 = no
sub get_mode { return 0};

1;