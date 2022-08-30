#!/usr/bin/perl
# Script to provide configuration to A10 aGalaxy appliance version 3.2.2 and 5.0.1.77 b77
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>, Vojtech Hodes <vojtech.hodes@flowmon.com>, Jiri Krejcir <jiri.krejcir@flowmon.com>
# Version: 2.9

package aGalaxyClient;
use strict;
use warnings;
use Exporter;
use REST::Client;
use Digest::MD5 qw(md5_hex);
use JSON;
use HTTP::Request::Common;
use Net::SSL;
use Net::IP;
use POSIX qw(strftime);
use Math::Round;
use Data::Dump qw(dump);
# Added DBI module for SQLite support
use DBI;
use 5.010;
use IPC::System::Simple qw(system capture);

require '/data/components/agalaxyclient/etc/aGalaxyConfig.pl';

my $username = get_user();
my $password = get_password();
my $ip = get_ip();
my $debug = get_debug();
my $client = undef;
my $get_mode = get_mode();

# database configuration
# install "libdbd-sqlite3-perl" package to support SQLite DB
my $driver = "SQLite";
my $database = "/data/components/agalaxyclient/etc/attacks.db";
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $pass = "";
#

# Here we take the only argument of script which is file name where is stored
# the detail of attack in JSON format
my ($iad_parametres_file) = $ARGV[0];
my ($template) = $ARGV[1] || "Flowmon_zone_template";
my ($group) = $ARGV[2] || "flowmon";
my ($start_mitigation);
# verify if mitigation should be started default is yes
if (exists $ARGV[3]) {
  if ($ARGV[3] eq 'yes') {
    $start_mitigation = 1;
  } else {
    $start_mitigation = 0;
  }
} else {
  $start_mitigation = 1;
}

# Load the details into the string
open (FILE, $iad_parametres_file) or die "Couldn't open file: $!";
binmode FILE;
my $iad_params = <FILE>;
close FILE;
open (my $fh, ">>", "/data/components/agalaxyclient/log/iad.log");

# Open connection into attackDB
my $dbh = connectDB();

if (not defined $iad_parametres_file) {
  print {$fh} localtime() . " FATAL: Parameter with attack not passed from the script!\n";
  die "Fatal: Parameter not passed from the script, exiting";
}

my $decoded = decode_json($iad_params);
my $attsub = join(', ' , @{$$decoded{'subnets_atk'}});
my $attstart = scalar(localtime($$decoded{'attackstart'}));
my $message = 'Hi,\n\nSegment: '.$$decoded{'segment'}.' (subnets: '.$attsub.')\nTime: '.$attstart.'\nEvent type: '.$$decoded{'event'}.'\nMitigation status: ';
my $subject = $$decoded{'segment'}." - ".$$decoded{'event'}." - ".$attstart;

# Login into the appliance and set up needed token
my $return = clientLogin();

my $zones;
if ( $template eq "install" ) {
  if ($return ne 'fail') {
    install();
  } else {
    if ($debug){
      print {$fh} localtime() . " DEBUG: Instalation failed.\n";
    }
  }
}
else {
  # Attack started we will need to configure a device
  if ($$decoded{'event'} eq 'statistics') {
    if ($return ne 'fail') {
      print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " detected, attack signature: ".$$decoded{'attacksignature'}."\n";
      my $name = zoneName($$decoded{'segment'}, $$decoded{'attackId'});
      checkDB();

      if ( get_sleep() ) {
        my $sleeper = int rand(16);
        if($debug){
          print {$fh} localtime() . " DEBUG: Sleep " . $sleeper ."s before zone name check\n";
        }
        sleep $sleeper;
      }

      $zones = getZones($name);
      my ($exist, $orig) = checkZone($name);
      if ($exist) {
        # first we create DOS profile
        createZone($name);
      } else {
        # zone exists, do we need to modify it?
        print {$fh} localtime() . " INFO: The zone already exist, no configuration applied.\n";
      }

      print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
    }
    else {
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Connection to aGalaxy was not established.\n";
      }
    }
  }
  # Attack signature is updated so let's update the zone as well
  elsif ($$decoded{'event'} eq 'signature_update') {
    if ($return ne 'fail') {
      print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " updated, attack signature: ".$$decoded{'attacksignature'}."\n";
      checkDB();
      my $name = zoneName($$decoded{'segment'}, $$decoded{'attackId'});
      $zones = getZones($name);
      my ($exist, $orig) = checkZone($name);

      if ($exist) {
        print {$fh} localtime() . " ERROR: The zone $name does not exist, cannot make its update.\n";
        createZone($name);
      } else {
        print {$fh} localtime() . " INFO: Updating zone $name\n";
        modifyZone($name);
      }
      print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
    }
    else {
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Connection to aGalaxy was not established.\n";
      }
    }
  }

  # Attack is over so it's time to remove the config from device
  elsif ($$decoded{'event'} eq 'ended') {
    if ($return ne 'fail') {
      checkDB();
      print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
      print {$fh} localtime() . " INFO: Deleting profiles from appliance\n";

      # Execute removal from TPS, if dual mode is turned on
      if ($get_mode) {
        my $tpsentry = $dbh->selectrow_array("SELECT COUNT(id) FROM a10 WHERE type = 'TPS' AND ATTACKID = $$decoded{'attackId'}");
          # Check if we have any zone on TPS. If yes, delete on TPS directly
          if ($tpsentry gt 0) {
            # call TPS script and pass the arguments from the DDoS Defender call
            system($^X, "../a10client/a10client.pl", $ARGV[0]);
          }
      }
      deleteZone(zoneName($$decoded{'segment'}, $$decoded{'attackId'}));
    } else {
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Connection to aGalaxy was not established.\n";
      }
      storeDB();
    }
  } else {
    print {$fh} localtime() . " INFO: Unconfigured action detected, exiting.\n";
  }
}
if ($return ne 'fail') {
  $return = clientLogoff();
}

# Disconnect from attackDB
disconnectDB();

###################################################################################
# General Function

# Check Agalaxy version
#
sub getAgalaxyVersion {
  $client->GET("/agapi/v1/system/");
  if ($client->responseCode() eq '200') {
    my $decoded = decode_json($client->responseContent());
    my @version = split(/\./,$$decoded{'version'});

    if ($debug) {
	print {$fh} localtime() . " DEBUG: AGalaxy version: " . $version[0] ."\n";
    }
    return $version[0];

  }
  else
  {
    print {$fh} localtime() . " INFO: AGalaxy version is not availabe.\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
    return 0;
  }
}


# To generate unique and safe zone name
# string $zone_name Segment name from DDD
# int $attack_id ID of attack
sub zoneName {
  my ($zone_name, $attack_id) = @_;

  $zone_name =~ s/\s+//g; # remove whitespaces
  $zone_name =~ s/_/-/g; # replace underscore in names as it can make problems to TPS
  $zone_name =~ s/[\$#@~!&*()\[\];.,:?^ `\\\/]+//g; # remove special characters

  my $first_name = substr($zone_name, 0, 10); # take first 10 characters
  $zone_name = md5_hex($zone_name); # And compute MD5 of theeverything in HEX

  my $retval = $attack_id ."-". $first_name ."-".$zone_name;

  return $retval;
} # end sub zoneName

# This function is to ensure that IP follows the RFC
sub ipAddressNormalize {
    my $address = shift();

    my ($ip, $len, $ipversion, $curr_bin, $rest);
    my $retval = undef;

    if ($address =~ m!^(\S+?)(/\S+)$!) {
        ($ip, $len) = ($1, $2);

        return undef unless ($ipversion = Net::IP::ip_get_version($ip));
        return undef unless ($ip = Net::IP::ip_expand_address($ip, $ipversion));
        return undef unless ($curr_bin = Net::IP::ip_iptobin($ip, $ipversion));
        if (defined $len) {
            return undef unless ($len =~ s!^/(\d+)(\,|$)!!);
            $len = $1;

            return undef if ($len > 128);
            return undef if (($len > 32) && ($ipversion == 4));

            $rest = substr($curr_bin, $len);
            $rest =~ s/1/0/g;
            substr($curr_bin, $len) = $rest;

            $retval = Net::IP::ip_bintoip($curr_bin, $ipversion) . "/" . $len;
        } else {
            $retval = $ip;
        }
    }
} # end ipAddressNormalize()

# Function to work on array to get out unwanted keys.
sub process_hash {
    my $ref = shift();

    foreach my $key (keys %{$ref}) {
      if ($key eq 'uuid') {
        delete($$ref{$key});
      }
      elsif ($key eq 'url') {
        delete($$ref{$key});
      }
      elsif ($key eq 'zone_threshold_num')
      {
        my $item = $$ref{$key};

        $item =~ /(.*)(...)/;

        my $id = $1;
        my $pr = $2;
        $pr = $pr / 100;
        #*********************************************************************************
        # replace keys with matching values in template from learned baselines
        # based on following IDs
        # 2110201 TCP PPS
        # 2110202 UDP PPS
        # 2110203 443 PPS
        # 2110204 80 PPS
        # 2110205 53 PPS
        # 2110206 ICMP PPS
        # 2110207 General PPS
        #
        # 2110101 TCP BPS
        # 2110102 UDP BPS
        # 2110103 443 BPS
        # 2110104 80 BPS
        # 2110105 53 BPS
        # 2110106 ICMP BPS
        # 2110107 General BPS
        # After the ID there needs to be three numbers 000 - 999 with meaning how much
        # of the baseline should be inserted into the template 0 - 999%
        #********************************************************************************#
        my %baseline = ( "2110201" => round( $$decoded{'pps_tcp'} * $pr ),
                         "2110202" => round( $$decoded{'pps_udp'} * $pr ),
                         "2110203" => round( $$decoded{'pps_https'} * $pr ),
                         "2110204" => round( $$decoded{'pps_http'} * $pr ),
                         "2110205" => round( $$decoded{'pps_dns'} * $pr ),
                         "2110206" => round( $$decoded{'pps_icmp'} * $pr ),
                         "2110207" => round( $$decoded{'pps'} * $pr ),
                         "2110101" => round( $$decoded{'bandwidth_tcp'} * $pr ),
                         "2110102" => round( $$decoded{'bandwidth_udp'} * $pr ),
                         "2110103" => round( $$decoded{'bandwidth_https'} * $pr ),
                         "2110104" => round( $$decoded{'bandwidth_http'} * $pr ),
                         "2110105" => round( $$decoded{'bandwidth_dns'} * $pr ),
                         "2110106" => round( $$decoded{'bandwidth_icmp'} * $pr ),
                         "2110107" => round( $$decoded{'bandwidth'} * $pr ));
        # add matching value
        $$ref{$key} = $baseline{$id};
      }
      else {
        process($$ref{$key});
      }
    }
}

sub process_array {
    my $ref = shift();

    my $index = 1;
    foreach my $item (@{$ref}) {
        process($item);
        $index++;
    }
}

sub process {
    my $ref = shift();

    if (!ref($ref)) {
        # Not a reference
        process(\$ref);
    }
    elsif ( UNIVERSAL::isa($ref,'HASH') ) {
        # Reference to a hash
        process_hash($ref);
    }
    elsif ( UNIVERSAL::isa($ref,'ARRAY') ) {
        # Reference to an array
        process_array($ref);
    }
}

################################################################################
# API functions

#-------------------------------------------------------------------------------
# Function to login into the aGalaxy in order to be able to start commanding it
# no parameters are required here
sub clientLogin {

    my $retval;

    my $ua = LWP::UserAgent->new( cookie_jar => {} );
    $client = REST::Client->new( { useragent => $ua } );
    $client->getUseragent()->ssl_opts( 'verify_hostname' => 0 );
    $client->setHost('https://'.$ip);
    $client->addHeader('Content-Type', 'application/json');
    $client->addHeader('Accept', 'application/json');

    $client->POST('/agapi/auth/login/', '{"credentials": {"username": "'.$username.'", "password": "'.$password.'"}}');

    if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " INFO: Connected to aGalaxy " .$ip. " successfully.\n";
        $retval = $client->responseCode();
    } else {
        $retval = $client->responseCode();

        if ($client->responseCode() eq '403') {
            print {$fh} localtime() . " ERROR: Authentication to aGalaxy " .$ip. " failed.\n";
            if ($debug) {
              print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
            }
            $retval = "fail";
        }
        ### unable to connect
        elsif ($client->responseCode() eq '500') {
            print {$fh} localtime() . " ERROR: Connection to aGalaxy " .$ip. " failed. No such host.\n";
            if ($debug) {
              print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
            }
            $retval = "fail";
        } else {
            print {$fh} localtime() . " ERROR: Connection to aGalaxy " .$ip. " failed. General error.\n";
            if ($debug) {
              print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
            }
            $retval = "fail";
        }
    }

    return $retval;
} # end clientLogin()

# ----------------------------------------------------------------------
# Function to log off the client after commands are issued
# no params here
sub clientLogoff {
  my $retval;

  $client->POST('/agapi/auth/logout/');

  if ($client->responseCode() eq '204') {
    print {$fh} localtime() . " INFO: Disconnected from aGalaxy " .$ip. " successfully.\n";
    return 0;
  }
  elsif ($client->responseCode() eq '403') {
    print {$fh} localtime() . " ERROR: Logoff from aGalaxy " .$ip. " failed.\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
    $retval = "authentication";
  }
  elsif ($client->responseCode() eq '500') {
    print {$fh} localtime() . " ERROR: Connection to aGalaxy " .$ip. " failed. No such host.\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
     $retval = "host";
  } else {
    print {$fh} localtime() . " ERROR: Connection to aGalaxy " .$ip. " failed. General error.\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
    $retval = "generic";
  }
} #end clientLogoff()

#-------------------------------------------------------------------------------
# Function to create a DDoS zone to protect a segment
# string $zone_name name of zone to be created
# string $subnet protected network segment
sub createZone {

  my $retval;
  my ($zone_name, $subnet) = @_;

  my @tcp_ports;
  my @udp_ports;
#  my @icmp_type;
  my %tcp_hash;
  my %udp_hash;
#  my %icmp_hash;

  my ($port, $protocol) = (0, 'other');
  my $sig_len = length($$decoded{'attacksignature'});
  if ($sig_len eq 0) {
    # Signature is empty
    print {$fh} localtime() . " INFO: Zone " .$zone_name. " not created, the signature is empty.\n";
    return 0;
  }
  # parse through the attack signature to find ports and protocol used for attack
  my @signature_piceses = split( / OR /, $$decoded{'attacksignature'} );
  foreach my $rule (@signature_piceses) {

    if ($rule =~ /destination-port =(\d+)[ ,)]/) {
      $port = $1;
    }

    if ($rule =~ /protocol (\w+)[ ,)]/) {
      $protocol = $1;
    }
# TODO ICMP
    #icmp detection
 #   if ($rule =~ /icmp-type (\w+)[ ,)]/){
 #     $protocol = $1;
 #   }

    if ($protocol eq '6') {
      $tcp_hash{$port} = 1;

    } elsif ( $protocol eq '17' ) {
      $udp_hash{$port} = 1;
    }
# TODO ICMP
  #  } elsif ( $protocol eq '1' ){
  #    $icmp_hash{$port} = 1;
  #  }

## when no test true create general TCP+UDP other rule (protocol 0)
    else {
      $tcp_hash{$port} = 1;
      $udp_hash{$port} = 1;
    }
  }

    @tcp_ports = keys %tcp_hash;
    @udp_ports = keys %udp_hash;
# TODO ICMP

  # check if there is a FlowmonTemplate DOS profile on appliance
  $client->GET("/agapi/v1/ddos/zone/?zone_name=" . $template);
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Template " . $template . " exist will use it for zone creation.\n";
    my $zone_tmp = decode_json($client->responseContent());
    my $zone_template = $$zone_tmp[0];

    $$zone_template{'zone_name'} =  $zone_name;
    $$zone_template{'description'} = "Flowmon DDoS zone for Attack ID ".$$decoded{'attackId'};

    # lets get device group for mitigation
    $client->GET("/agapi/v1/device-group/?group_name=".$group);
    if ($client->responseCode() eq '200') {
      my $device_list = decode_json($client->responseContent());
      $$zone_template{'device_group'} = $$device_list{'device_group_list'}[0]{'id'};
    }
    else
    {
      print {$fh} localtime() . " INFO: Device group " . $group . " does not exists.\n";
      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
    }


    process($zone_template);

    my @ip_list;

    # We will go through configured subnets and create ip list for all of them
    foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
      # Parse the IP to get IP and MASK
      my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());

      # does IP already exists
      if (checkIP($subnet))
      {
        # let's check if it's IP v4 or v6
        if ($ip_seg->version() == 4)
        {
          # if there is only a host mitigation we will use IP only for a profile
          if ($ip_seg->prefixlen() == 32) {
            $subnet = $ip_seg->ip();
            push(@ip_list, $subnet);
          }
          else {
            push(@ip_list, $subnet);
          }
        }
        else {
          if ($ip_seg->prefixlen() == 128) {
            $subnet = $ip_seg->ip();
            push(@ip_list, $subnet);
          }
          else {
            push(@ip_list, $subnet);
          }
        }
      }
    }

    if (!@ip_list) {
      # IP list is empty
      print {$fh} localtime() . " INFO: Zone " .$zone_name. " not created, the IP list was empty.\n";
      return 0;
    }

    # Add IPs to the zone template
    $$zone_template{"ip_list"} = \@ip_list;

    # TODO add port under attack in case it's not listed, we should protect those in case there is nothing

    # send profile to appliance to create it
    $client->POST('/agapi/v1/ddos/zone/', encode_json($zone_template));
    my $json_hash_ref = decode_json($client->responseContent());

    if ($client->responseCode() eq '201') {
      print {$fh} localtime() . " INFO: Zone " .$zone_name. " successfully created from template " . $template . ".\n";

      # send notificatin if we are successfull
      if (get_notification()) {
        system("/data/components/agalaxyclient/api/dddNotification.py send -a ".$$decoded{'attackId'});
      }
      # now we need to create incidents for all detected services
      #
      #
      foreach my $port (@tcp_ports) {
        if ($port == 80) {
          createIncident($zone_name, "80+http");
        } elsif ($port == 53) {
          createIncident($zone_name, "53+dns-tcp");
        } elsif ($port == 443) {
          createIncident($zone_name, "443+ssl-l4");
        } elsif ($port == 0) {
          createIncident($zone_name, "other+tcp");
        } elsif (createIncident($zone_name, $port."+tcp")) {
          # in case of failure create general incident for TCP
          createIncident($zone_name, "other+tcp");
        }
      }
      foreach my $port (@udp_ports) {
        if ($port == 53) {
          createIncident($zone_name, "53+dns-udp");
        } elsif ($port == 0) {
          createIncident($zone_name, "other+udp");
        } elsif (createIncident($zone_name, $port."+udp")) {
          # in case of failure create general incident for UDP
          createIncident($zone_name, "other+udp");
        }
      }
      # TODO ICMP


      if ($start_mitigation)
      {
        startMitigation($zone_name, $$json_hash_ref{'id'});
      }

      $retval = $client->responseCode();
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Zone " .$zone_name. " from template " . $template . " was not created. Error: ".$$json_hash_ref{'message'}."\n";

      # send notification that it failed
      if (get_noc_send()) {
        $message .= "Zone creation failed. Error: ".$$json_hash_ref{'message'};
        system("/usr/bin/php /var/www/shtml/index.php Cli:SendEmail -to=".get_noc()." -body=\"`echo -e '".$message."'`\" -subject='".$subject."'");
      }

      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
    }
  }
  else
  # Template does not exist or was not handed over in parameter so we shall use template for standard attacks
  {
    print {$fh} localtime() . " INFO: Template " . $template . " doesn't exist. Using built-in zone.\n";
    my @ip_list;
    # We will go through configured subnets and create ip list for all of them
    foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
      # does IP already exists
      if (checkIP($subnet))
      {
        # Parse the IP to get IP and MASK
        my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());

        # let's check if it's IP v4 or v6
        if ($ip_seg->version() == 4)
        {
          # if there is only a host mitigation we will use IP only for a profile
          if ($ip_seg->prefixlen() == 32) {
            $subnet = $ip_seg->ip();
            push(@ip_list, $subnet);;
          }
          else {
            push(@ip_list, $subnet);
          }
        }
        else {
          if ($ip_seg->prefixlen() == 128) {
            $subnet = $ip_seg->ip();
            push(@ip_list, $subnet);
          }
          else {
            push(@ip_list, $subnet);
          }
        }
      }
    }

    if (!@ip_list) {
      # IP list is empty
      print {$fh} localtime() . " INFO: Zone " .$zone_name. " not created, the IP list was empty.\n";
      return 0;
    }

    my @service_list;
    my @level_list_tcp;
    my @level_list_udp;

    my %level0_tcp = ("level_num" => "0",
                  "zone_template" => { "tcp" => "TCP_0" },
                  "zone_escalation_score" => 10,
                  "indicator_list" => [
                    { "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => $$decoded{'pps_tcp'} }
                                       ] );
    my %level1_tcp = ("level_num" => "1",
                  "zone_template" => { "tcp" => "TCP_1" },
                  "zone_escalation-score" => 10,
                  "indicator_list" => [
                    { "type" => "pkt-rate",
                    "score" => 20 }
                                       ] );
    push (@level_list_tcp, \%level0_tcp, \%level1_tcp);

    my %level0_udp = ("level_num" => "0",
                  "zone_template" => { "udp" => "UDP_0" },
                  "zone_escalation-score" => 10,
                  "indicator_list" => [
                    { "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => $$decoded{'pps_udp'} }
                                       ] );
    my %level1_udp = ("level_num" => "1",
                  "zone_template" => { "udp" => "UDP_1" },
                  "zone_escalation-score" => 10,
                  "indicator_list" => [
                    { "type" => "pkt-rate",
                    "score" => 20 }
                                       ] );
    push (@level_list_udp, \%level0_udp, \%level1_udp);

    foreach my $port (@tcp_ports) {
      if ($port > 0) {
        my %port_config = ("port" => $port,
                            "protocol" => "tcp",
                            "level_list" => \@level_list_tcp);
        push (@service_list, \%port_config);
      }
    }
    foreach my $port (@udp_ports) {
      if ($port > 0) {
        my %port_config = ("port" => $port,
                            "protocol" => "udp",
                            "level_list" => \@level_list_udp);
        push (@service_list, \%port_config);
      }
    }

    my @src_port;
    my %port_19 = ( "deny" => 1,
                    "port" => 19,
                    "protocol" => "udp" );
    my %glid_cfg = ( "glid" => "Strict_Rate_Limit" );
    my %port_53 = ( "deny" => 0,
                    "port" => 53,
                    "protocol" => "udp",
                    "glid_cfg" => \%glid_cfg );
    my %port_111 = ( "deny" => 1,
                    "port" => 111,
                    "protocol" => "udp" );
    my %port_123 = ( "deny" => 0,
                    "port" => 123,
                    "protocol" => "udp",
                    "glid_cfg" => \%glid_cfg );
    my %port_137 = ( "deny" => 1,
                    "port" => 137,
                    "protocol" => "udp" );
    my %port_161 = ( "deny" => 1,
                    "port" => 161,
                    "protocol" => "udp" );
    my %port_1434 = ( "deny" => 1,
                    "port" => 1434,
                    "protocol" => "udp" );
    my %port_1900 = ( "deny" => 1,
                    "port" => 1900,
                    "protocol" => "udp" );
    push (@src_port, \%port_19, \%port_53, \%port_111, \%port_123, \%port_137, \%port_161, \%port_1434, \%port_1900);
    my %src_port = ( "zone_src_port_list" => \@src_port );

    my @service_other_list;
    my %item1 = ("port_other" => "other",
                 "protocol" => "tcp",
                 "deny" => 0,
                 "enable_top_k" => 1);
    my %item2 = ("port_other" => "other",
                 "protocol" => "udp",
                 "deny" => 0,
                 "enable_top_k" => 1);

    # TODO add ICMP and non-IP porotocols
    push (@service_other_list, \%item1, \%item2);

    if(!@service_list) {
      print {$fh} localtime() . " INFO: There are no ports in signature skipping service_list configuration\n";
    }

    my %port_list = ( "zone_service_list" => \@service_list,
                      "zone_service_other_list" => \@service_other_list);

    my %proto_other = ("protocol" => "other",
                       "deny" => 0,
                       "enable_top_k" => 1);
    my @ip_proto;
    push (@ip_proto, \%proto_other);

    $client->GET("/agapi/v1/device-group/?group_name=".$group);

    my %zone = ( "zone_name" => $zone_name,
                 "port" => \%port_list,
                 "ip_proto_list" => \@ip_proto,
                 "description" => "Flowmon DDoS zone for Attack ID " . $$decoded{'attackId'},
                 "ip_list" => \@ip_list,
                 "src_port" => \%src_port,
		 "zone_oper_policy_name" => "null",
		 "force_push" => "true"
                );

    if ($client->responseCode() eq '200') {
      my $device_list = decode_json($client->responseContent());
      $zone{'device_group'} = $$device_list{'device_group_list'}[0]{'id'};
    }
    else
    {
      print {$fh} localtime() . " INFO: Device group " . $group . " does not exists.\n";
      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
    }

    $client->POST( '/agapi/v1/ddos/zone/', encode_json(\%zone) );

    my $json_hash_ref = decode_json($client->responseContent());
    print $client->responseContent();
    if ($client->responseCode() > '201') {
      $retval = "host";
      print {$fh} localtime() . " ERROR: Cannot create a zone $zone_name! Error: ".$$json_hash_ref{'message'}."\n";
      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
      if (get_noc_send()) {
        $message .= "Zone creation failed. Error: ".$$json_hash_ref{'message'};
        system("/usr/bin/php /var/www/shtml/index.php Cli:SendEmail -to=".get_noc()." -body=\"`echo -e '".$message."'`\" -subject='".$subject."'");
      }
    }
    elsif ($client->responseCode() eq '201') {
      print {$fh} localtime() . " INFO: Zone $zone_name created successfully.\n";
      # now we need to create incidents for all detected services
      if (get_notification()) {
        system("/data/components/agalaxyclient/api/dddNotification.py send -a ".$$decoded{'attackId'});
      }
      foreach my $port (@tcp_ports) {
        if (createIncident($zone_name, $port."+tcp")) {
          # in case of failure create general incident for TCP
          createIncident($zone_name, "other+tcp");
        }
      }
      foreach my $port (@udp_ports) {
        if (createIncident($zone_name, $port."+udp")) {
          # in case of failure create general incident for UDP
          createIncident($zone_name, "other+udp");
        }
      }

      if ($start_mitigation)
      {
        startMitigation($zone_name, $$json_hash_ref{'id'});
      }

      $retval = $client->responseCode();
    }
  }

  return $retval;
} # end createZone

#-------------------------------------------------------------------------------
# Function to modify existing DDoS zone
# string $zone_name name of zone to be updated
# string $subnet protected network segment
sub modifyZone {
  #my $retval;
  my ($zone_name, $subnet) = @_;

  my @tcp_ports;
  my @udp_ports;
  my %tcp_hash;
  my %udp_hash;
  
  my $sig_len = length($$decoded{'attacksignature'});
  if ($sig_len eq 0) {
    # Signature is empty
    print {$fh} localtime() . " INFO: Zone " .$zone_name. " not created, the signature is empty.\n";
    return 0;
  }
  # parse through the attack signature to find ports and protocol used for attack
  my @signature_piceses = split( / OR /, $$decoded{'attacksignature'} );
  foreach my $rule (@signature_piceses) {
    my ($port, $protocol) = (0, undef);

    if ($rule =~ /destination-port =(\d+)[ ,)]/) {
      $port = $1;
    }

    if ($rule =~ /protocol (\w+)[ ,)]/) {
      $protocol = $1;
    }

    if ($protocol eq 'tcp') {
      $tcp_hash{$port} = 1;
    } elsif ( $protocol eq 'udp' ) {
      $udp_hash{$port} = 1;
    }
  }

  @tcp_ports = keys %tcp_hash;
  @udp_ports = keys %udp_hash;


  my @ip_list;

  # We will go through configured subnets and create ip list for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    # Parse the IP to get IP and MASK
    my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());

    # let's check if it's IP v4 or v6
    if ($ip_seg->version() == 4)
    {
      # if there is only a host mitigation we will use IP only for a profile
      if ($ip_seg->prefixlen() == 32) {
        $subnet = $ip_seg->ip();
        push(@ip_list, $subnet);
      }
      else {
        push(@ip_list, $subnet);
      }
    }
    else {
      if ($ip_seg->prefixlen() == 128) {
        $subnet = $ip_seg->ip();
        push(@ip_list, $subnet);
      }
      else {
        push(@ip_list, $subnet);
      }
    }
  }

  # get zone ID in order to modify it
  $client->GET("/agapi/v1/ddos/zone/?zone_name=" . $zone_name);
  if ($client->responseCode() eq '200') {

    print {$fh} localtime() . " INFO: Zone " . $zone_name . " found and will be modified.\n";
    my $zone = decode_json($client->responseContent());

    # update a zone with new a subnet to be mitigated
    $$zone[0]{"ip_list"} = \@ip_list;

    # send the updated zone to aGalaxy
    my $encoded = encode_json($$zone[0]);
    $client->PUT('/agapi/v1/ddos/zone/'.$$zone[0]{id}.'/', $encoded);
    if ($client->responseCode() eq '200') {
      print {$fh} localtime() . " INFO: Zone " .$zone_name. " successfully updated."."\n";
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Zone " .$zone_name. " was not updated. Error: " .  $client->responseCode() . ":" . dump($json_hash_ref)."\n";
    }

  } else {
      print {$fh} localtime() . " INFO: Zone " . $zone_name . " not found.\n";
  }

} # end of modifyZone();

#-------------------------------------------------------------------------------
# Function to create an incident on zone
# string $zone_name name of zone to create incident
# string $incident incident to create
sub createIncident {
  my ($zone_name, $incident) = @_;
  my $note = substr($$decoded{'segment'},0,254);
  my %my_incident = ( "name" => $zone_name.'-'.$incident,
                   "zone" => $zone_name,
                   "service" => $incident,
                   "note" => $note,
                   "level" => "0");

  $client->POST( '/agapi/v1/ddos/zone/incident/', encode_json(\%my_incident) );

  if ($client->responseCode() > '201') {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " INFO: Cannot create an incident for zone $zone_name! Message: ".$$json_hash_ref{'message'}."\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
    return 1; # failure
  }
  elsif ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone $zone_name incident $incident created successfully.\n";

    return 0; # success
  }
} #end createIncident

#-------------------------------------------------------------------------------
# This is here to start mitigation on zone
# string $id ID of zone where we are going to start mitigation
sub startMitigation {
  my ($zone_name, $id) = @_;
  $client->POST('/agapi/v1/ddos/zone/'.$id.'/mitigation/start/');

  if ($client->responseCode() > '202') {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " INFO: Cannot start mitigation for zone $zone_name! Message: ".$$json_hash_ref{'message'}."\n";
    if ($debug) {
     print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  elsif ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone $zone_name mitigation started successfully.\n";
  }
} # end startMitigation

#-------------------------------------------------------------------------------
# Function to delete the zone from the configuration
# string $zone_name name of zone to be deleted
sub deleteZone {

  my $retval;
  my ($zone_name) = @_;


  $client->GET("/agapi/v1/ddos/zone/?zone_name=" . $zone_name);
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone " . $zone_name . " found and will be deleted.\n";
    my $zone = decode_json($client->responseContent());
    stoptMitigation($zone_name, $$zone[0]{id});
    # should we delete also incident or not?
    if ( get_delete_incident() ) {
      deleteIncident($zone_name);
    }
    $client->DELETE('/agapi/v1/ddos/zone/'.$$zone[0]{id}.'/');
  }
  else
  {
    print {$fh} localtime() . " INFO: Zone " . $zone_name . " not found.\n";
  }

  if ($client->responseCode() > '204') {
    $retval = "host";
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " INFO: Cannot delete a zone $zone_name! Message: ".$$json_hash_ref{'message'}."\n";

    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  elsif ($client->responseCode() eq '204') {
    print {$fh} localtime() . " INFO: Zone $zone_name deleted successfully.\n";
    $retval = $client->responseCode();
  }
} # end deleteZone

#-------------------------------------------------------------------------------
# This is here to stop mitigation on zone
# string $id ID of zone where we are going to start mitigation
sub stoptMitigation {
  my ($zone_name, $id) = @_;
  $client->POST('/agapi/v1/ddos/zone/'.$id.'/mitigation/stop/');

  if ($client->responseCode() > '202') {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " INFO: Cannot stop mitigation for zone $zone_name! Message: ".$$json_hash_ref{'message'}."\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  elsif ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone $zone_name mitigation stopped successfully.\n";
  }
} # end startMitigation

#-------------------------------------------------------------------------------
# Here ve will delete all created incidents for the zone
sub deleteIncident {
  my ($zone_name) = @_;
  $client->GET("/agapi/v1/ddos/zone/incident/?zone_name=" . $zone_name);
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone " . $zone_name . " incidents found and will be deleted.\n";
    my $zone = decode_json($client->responseContent());
    foreach my $service (keys %{$zone}) {
      $client->DELETE('/agapi/v1/ddos/zone/incident/'.$$zone[$service]{id}.'/');
    }
  }
  else {
    print {$fh} localtime() . " INFO: Zone " . $zone_name . " incidents not found.\n";
  }
} # end deleteIncident

# ------------------------------------------------------------------------------
# Function to install all required configuration into the A10 aGalaxy box
# no parameters here
sub install {
  print {$fh} localtime() . " INFO: Starting installation procedure to prepare aGalaxy for integration with Flowmon.\n";
  ###############################################################################
  # Create GLID
  print {$fh} localtime() . " INFO: Creating GLID Strict_Rate_Limit.\n";
  my %glid_config = ( "glid" => { "name" => "Strict_Rate_Limit",
               "description" => "Apply to objects with expected low PPS",
               "pkt_rate_limit" => "1000" } );
  # send GLID to appliance to create it
  $client->POST('/agapi/v1/glid/', encode_json(\%glid_config));
  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: GLID Strict_Rate_Limit successfully created.\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: GLID Strict_Rate_Limit was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
  }
  #############################################################################
  # Create zone templates for protections
  print {$fh} localtime() . " INFO: Creating required zone-templates.\n";
  my %type0_rate = ( "dst_type_rate" => 100 );
  my %type0 = ( "type_number" => 0,
                "v4_dst_rate_cfg" => \%type0_rate );
  my %type5 = ( "type_number" => 5,
                "icmp_type_action" => "drop" );
  my %type8 = ( "type_number" => 8,
                "icmp_type_action" => "drop" );
  my %type9 = ( "type_number" => 9,
                "icmp_type_action" => "drop" );
  my %type10 = ( "type_number" => 10,
                "icmp_type_action" => "drop" );
  my %type11 = ( "type_number" => 11,
                "icmp_type_action" => "drop" );
  my %type14 = ( "type_number" => 14,
                "icmp_type_action" => "drop" );
  my @icmp_type;
  push (@icmp_type, \%type0, \%type5, \%type8, \%type9, \%type10, \%type11, \%type14);
  my %icmp = ( "name" => "ICMP_v4_Basic",
               "type_list" => \@icmp_type );

  # send ICMP template to appliance to create it
  $client->POST('/agapi/v1/ddos/zone/template/icmpv4/', encode_json(\%icmp));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone template ICMP_v4_Basic successfully created.\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template ICMP_v4_Basic was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
  }
  ########################
  my %dst_t_i = ( "rate_limit" => { "request" => { "type" => {
                  "A_cfg" => { "A" => 1, "dns_a_rate" => 50000 },
                  "AAAA_cfg" => { "AAAA" => 1, "dns_aaaa_rate" => 1000 },
                  "MX_cfg" => { "MX" => 1, "dns_mx_rate" => 1000 },
                  "NS_cfg" => { "NS" => 1, "dns_ns_rate" => 1000 }
                } } } );
  my %mal_query = ( "validation_type" => "extended-header-check" );
  my %dns_t_i = ( "name" => "DNS_TCP_Intermediate",
                  "dns_any_check" => 1,
                  "dst" => \%dst_t_i,
                  "malformed_query_check" => \%mal_query );
  my %dns_u_i = ( "name" => "DNS_UDP_Intermediate",
                  "dns_any_check" => 1,
                  "dst" => \%dst_t_i,
                  "malformed_query-check" => \%mal_query,
                  "dns_udp_authentication" => { "udp_timeout" => 5, "min_delay" => 3 } );
  my %dns_u_a = ( "name" => "DNS_UDP_Advanced",
                  "dns_any_check" => 1,
                  "dst" => \%dst_t_i,
                  "malformed_query_check" => \%mal_query,
                  "dns_udp_authentication" => { "force_tcp_cfg" => { "force_tcp" => 1 } } );
  my @dns_list;
  push (@dns_list, \%dns_t_i, \%dns_u_i, \%dns_u_a);

  foreach (@dns_list)
  {
    # send DNS template to appliance to create it
    $client->POST('/agapi/v1/ddos/zone/template/dns/', encode_json($_));

    if ($client->responseCode() eq '201') {
      print {$fh} localtime() . " INFO: Zone template for ".$$_{'name'}." successfully created.\n";
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Zone template for ".$$_{'name'}." was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
    }
  }
  ######################
  my %tcp_conf = ( "name" => "TCP_Intermediate",
                   "zero_win_cfg" => { "zero_win" => 16, "zero_win_action" => "drop" },
                   "syn_authentication" => { "syn_auth_type" => "send-rst", "syn_auth_rto" => 0 },
                   "ack_authentication" => { "ack_auth_timeout" => 3, "ack_auth_min_delay" => 1 }
                 );
  # send TCP template to appliance to create it
  $client->POST('/agapi/v1/ddos/zone/template/tcp/', encode_json(\%tcp_conf));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone template for TCP successfully created.\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for TCP was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
  }
  ####################
  my %udp_conf = ( "name" => "UDP_Intermediate",
                   "spoof_detect_retry_timeout" => 5 );
  # send UDP template to appliance to create it
  $client->POST('/agapi/v1/ddos/zone/template/udp/', encode_json(\%udp_conf));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone template for UDP successfully created.\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for UDP was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
  }
  ####################
  my %ssl_conf = ( "name" => "SSL_L4_Basic",
                   "renegotiation" => { "num_renegotiation" => 4 } );
  # send SSL template to appliance to create it
  $client->POST('/agapi/v1/ddos/zone/template/ssl-l4/', encode_json(\%ssl_conf));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone template for SSL successfully created.\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for SSL was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
  }
  ########################
  my %http_b = ( "name" => "HTTP_Basic",
                 "mss_timeout" => { "mss_percent" => 25, "number_packets" => 5 },
                 "slow_read" => { "min_window_size" => 1024, "min_window_count" => 15 },
                 "malformed_http" => { "malformed_http" => "check" } );
  my %http_i = ( "name" => "HTTP_Intermediate",
                 "mss_timeout" => { "mss_percent" => 25, "number_packets" => 5 },
                 "slow_read" => { "min_window_size" => 1024, "min_window_count" => 15 },
                 "malformed_http" => { "malformed_http" => "check" },
                 "challenge" => { "challenge_method" => "http-redirect" } );
  my @http_list;
  push (@http_list, \%http_b, \%http_i);

  foreach (@http_list)
  {
    # send HTTP template to appliance to create it
    $client->POST('/agapi/v1/ddos/zone/template/http/', encode_json($_));

    if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone template for ".$$_{'name'}." successfully created.\n";
    } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for ".$$_{'name'}." was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
    }
  }
  ####################
  my %violation_conf = ( "name" => "Blacklist_Source",
                         "blacklist_src" => 5 );
  # send Blacklist template to appliance to create it
  $client->POST('/agapi/v1/ddos/violation-actions/', encode_json(\%violation_conf));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Violation action Blacklist successfully created.\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Violation action Blacklist was not created. Error: ".$$json_hash_ref{'detail'}{'name'}[0]."\n";
  }

  #####################################################
  # Now lets create zone template
  my @service_list;

  # Service DNS - 53 UDP ##############################################
  my @ind0_53u;
  my @level_list_53u;
  my %list0_53u = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110205100 );
  push (@ind0_53u, \%list0_53u);
  my %level0_53u = ("level_num" => "0",
                "indicator_list" => \@ind0_53u);
  my @ind1_53u;
  my %list1_53u = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110205110 );
  push (@ind1_53u, \%list1_53u);
  my %zone1_53u = ( "dns" => "DNS_UDP_Intermediate" );
  my %level1_53u = ( "level_num" => "1",
                     "zone_template" => \%zone1_53u,
                     "indicator_list" => \@ind1_53u,
                     "src_escalation_score" => 10);
  my %zone2_53u = ( "dns" => "DNS_UDP_Advanced" );
  my %level2_53u = ( "level_num" => "2",
                     "zone_template" => \%zone2_53u );
  push (@level_list_53u, \%level0_53u, \%level1_53u, \%level2_53u);
  my %port_53u_config = ("port" => 53,
                        "protocol" => "dns-udp",
                        "deny" => 0,
                        "enable_top_k" => 1,
                        "level_list" => \@level_list_53u );
  # END Service DNS - 53 UDP ###########################################

  # Service DNS - 53 TCP ###############################################
  my @ind_53t;
  my @level_list_53t;

  my %list0_53t = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110205100 );
  push (@ind_53t, \%list0_53t);

  my %level0_53t = ("level_num" => "0",
                    "zone_escalation_score" => 10,
                    "indicator_list" => \@ind_53t);
  my %zone1_53t = ( "dns" => "DNS_TCP_Intermediate",
                    "tcp" => "TCP_Intermediate" );
  my %level1_53t = ( "level_num" => "1",
                     "zone_template" => \%zone1_53t );
  push (@level_list_53t, \%level0_53t, \%level1_53t);
  my %port_53t_config = ("port" => 53,
                        "protocol" => "dns-tcp",
                        "deny" => 0,
                        "enable_top_k" => 1,
                        "level_list" => \@level_list_53t );
  # END Service DNS - 53 TCP ###########################################

  # Service HTTP - 80 TCP ##############################################
  my @ind_80;
  my @level_list_80;

  my %list0_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110204100 );
  push (@ind_80, \%list0_80);
  my %zone0_80 = ( "http" => "HTTP_Basic" );
  my %level0_80 = ("level_num" => "0",
                    "zone_escalation_score" => 10,
                    "indicator_list" => \@ind_80,
                    "zone_template" => \%zone0_80 );
  my @ind1_80;
  my %list1_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110204110 );
  push (@ind1_80, \%list1_80);
  my %level1_80 = ("level_num" => "1",
                    "zone_escalation_score" => 10,
                    "indicator_list" => \@ind1_80,
                    "zone_template" => \%zone0_80 );
  my @ind2_80;
  my %list2_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110204120 );
  push (@ind2_80, \%list2_80);
  my %zone2_80 = ( "tcp" => "TCP_Intermediate",
                   "http" => "HTTP_Basic");
  my %level2_80 = ("level_num" => "2",
                    "zone_escalation_score" => 10,
                    "indicator_list" => \@ind2_80,
                    "zone_template" => \%zone2_80 );
  my @ind3_80;
  my %list3_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110204130 );
  push (@ind3_80, \%list3_80);
  my %zone3_80 = ( "tcp" => "TCP_Intermediate",
                   "http" => "HTTP_Intermediate");
  my %level3_80 = ("level_num" => "3",
                    "indicator_list" => \@ind3_80,
                    "zone_template" => \%zone3_80 );
  push (@level_list_80, \%level0_80, \%level1_80, \%level2_80, \%level3_80);
  my %port_80_config = ("port" => 80,
                        "protocol" => "http",
                        "deny" => 0,
                        "enable_top_k" => 1,
                        "level_list" => \@level_list_80 );
  # END Service HTTP - 80 TCP #########################################

  # Service HTaGalaxy - 443 TCP ###########################################
  my @ind_443;
  my @level_list_443;

  my %list0_443 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone_threshold_num" => 2110203100 );
  push (@ind_443, \%list0_443);
  my %level0_443 = ("level_num" => "0",
                    "zone_escalation_score" => 10,
                    "indicator_list" => \@ind_443 );
  my %zone1_443 = ( "tcp" => "TCP_Intermediate",
                    "ssl_l4" => "SSL_L4_Basic" );
  my %level1_443 = ("level_num" => "1",
                    "zone_escalation_score" => 10,
                    "zone_template" => \%zone1_443 );
  push (@level_list_443, \%level0_443, \%level1_443);
  my %port_443_config = ("port" => 443,
                        "protocol" => "ssl-l4",
                        "deny" => 0,
                        "enable_top_k" => 1,
                        "level_list" => \@level_list_443 );
  # END Service HTaGalaxy - 443 TCP ######################################

  push (@service_list, \%port_53t_config, \%port_53u_config, \%port_80_config, \%port_443_config);

  my @service_other_list;
  my @level_list_tcp;
  my @level_list_udp;
  my @ind_tcp;

  my %ind_tcp = ( "zone_threshold_num" => 2110201100,
                  "type" => "pkt-rate",
                  "score" => 20 );
  push (@ind_tcp, \%ind_tcp);
  my %level0_tcp = ( "level_num" => "0",
                     "zone_escalation_score"=> 10,
                     "src_escalation_score" => 10,
                     "indicator_list" => \@ind_tcp );
  my %zone1_tcp = ( "tcp" => "TCP_Intermediate" );
  my %level1_tcp = ( "level_num" => "1",
                     "zone_template"=> \%zone1_tcp );
  push (@level_list_tcp, \%level0_tcp, \%level1_tcp);
  my %item1 = ( "port_other" => "other",
                "protocol" => "tcp",
                "deny" => 0,
                "enable_top_k" => 1,
                "level_list" => \@level_list_tcp );
  my @ind_udp;
  my %ind_udp = ( "zone_threshold_num" => 2110202100,
                  "type" => "pkt-rate",
                  "score" => 20 );
  push (@ind_udp, \%ind_udp);
  my %level0_udp = ( "level_num" => "0",
                     "zone_escalation_score"=> 10,
                     "indicator_list" => \@ind_udp );
  my %zone1_udp = ( "udp" => "UDP_Intermediate" );
  my %level1_udp = ( "level_num" => "1",
                     "zone_template"=> \%zone1_udp );
  my %item2 = ( "port_other" => "other",
                "protocol" => "udp",
                "deny" => 0,
                "enable_top_k" => 1,
                "level_list" => \@level_list_udp );
  push (@service_other_list, \%item1, \%item2);

  my %port_list = ( "zone_service_list" => \@service_list,
                    "zone_service_other_list" => \@service_other_list);

  my @proto_name;
  my %proto_other = ("protocol" => "other",
                     "deny" => 0,
                     "enable_top_k" => 1,
                     "drop_frag_pkt" => 0 );
  my %proto_ipv6encap = ( "protocol" => "ipv6-encap",
                          "deny" => 0,
                          "tunnel_decap" => 0,
                          "drop_frag_pkt" => 0,
                          "tunnel_rate_limit" => 0,
                          "enable_top_k" => 1 );
  my %proto_ipv4encap = ( "protocol" => "ipv4-encap",
                          "deny" => 0,
                          "tunnel_decap" => 0,
                          "drop_frag_pkt" => 0,
                          "tunnel_rate_limit" => 0,
                          "enable_top_k" => 1 );
  my %proto_icpm6 = ("protocol" => "icmp-v6",
                     "deny" => 1,
                     "enable_top_k" => 1,
                     "drop_frag_pkt" => 0 );
  my @list_icmp4;
  my @ind0_icmp;
  my %ind0_icmp = ( "zone_threshold_num" => 2110206100,
                   "type" => "pkt-rate",
                   "score" => 20 );
  push (@ind0_icmp, \%ind0_icmp);
  my %level0_icmp = ( "level_num" => "0",
                      "zone_escalation_score" => 10,
                      "indicator_list" => \@ind0_icmp );
  my @ind1_icmp;
  my %ind1_icmp = ( "zone_threshold_num" => 2110206110,
                   "type" => "pkt-rate",
                   "zone_violation_actions" => "Blacklist_Source" );
  push (@ind1_icmp, \%ind1_icmp);
  my %zone1_icmp = ( "icmp_v4" => "ICMP_v4_Basic" );
  my %level1_icmp = ( "level_num" => "1",
                      "zone_template" => \%zone1_icmp,
                      "indicator_list" => \@ind1_icmp );
  push (@list_icmp4, \%level0_icmp, \%level1_icmp);
  my %proto_icmp4 = ("protocol" => "icmp-v4",
                     "deny" => 0,
                     "enable_top_k" => 1,
                     "drop_frag_pkt" => 1,
                     "level_list" => \@list_icmp4);
  my %proto_gre = ( "protocol" => "gre",
                    "deny" => 1,
                    "tunnel_decap" => 0,
                    "drop_frag_pkt" => 0,
                    "tunnel_rate_limit" => 0,
                    "enable_top_k" => 1 );

  push (@proto_name, \%proto_other, \%proto_ipv6encap, \%proto_ipv4encap, \%proto_icpm6, \%proto_icmp4, \%proto_gre);

  my @src_port;
  my %port_19 = ( "deny" => 1,
                  "port" => 19,
                  "protocol" => "udp" );
  my %glid_cfg = ( "glid" => "Strict_Rate_Limit" );
  my %port_53 = ( "deny" => 0,
                  "port" => 53,
                  "protocol" => "udp",
                  "glid_cfg" => \%glid_cfg );
  my %port_111 = ( "deny" => 1,
                  "port" => 111,
                  "protocol" => "udp" );
  my %port_123 = ( "deny" => 0,
                  "port" => 123,
                  "protocol" => "udp",
                  "glid_cfg" => \%glid_cfg );
  my %port_137 = ( "deny" => 1,
                  "port" => 137,
                  "protocol" => "udp" );
  my %port_161 = ( "deny" => 1,
                  "port" => 161,
                  "protocol" => "udp" );
  my %port_1434 = ( "deny" => 1,
                  "port" => 1434,
                  "protocol" => "udp" );
  my %port_1900 = ( "deny" => 1,
                  "port" => 1900,
                  "protocol" => "udp" );
  push (@src_port, \%port_19, \%port_53, \%port_111, \%port_123, \%port_137, \%port_161, \%port_1434, \%port_1900);
  my %src_port = ( "zone_src_port_list" => \@src_port );

  my %zone = ( "zone_name" => "Flowmon_zone_template",
               "description" => "Zone template for Flowmon DDoS Defender. !!!DO NOT DELETE!!!",
               "operational_mode" => "monitor",
               "log_enable" => 1,
               "log_periodic" => 1,
               "port" => \%port_list,
               "ip_proto_list" => \@proto_name,
               "ip_list" => [ "196.254.223.32" ],
               "src_port" => \%src_port
              );

  if($debug){
    print {$fh} localtime() . encode_json(\%zone) . "\n";
  }

  $client->POST('/agapi/v1/ddos/zone/', encode_json(\%zone));

  my $json_hash_ref = decode_json($client->responseContent());

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Zone Flowmon_zone_template created successfully.\n";
  }
  else {
    print {$fh} localtime() . " INFO: Cannot create a zone Flowmon_zone_template! Message: ".$$json_hash_ref{'message'}."\n";
  }
} # end install()

#------------------------------------------------------------------------------------------------
# Function to get all zones
# return reference to result
sub getZones {
  my $agversion = getAgalaxyVersion();
  if ($agversion < 5 ){
    # Get the list of all zones to see if there is one which matches
    $client->GET("/agapi/v1/ddos/zone/?count=1000");
  }
  else{
    my $hash = (split(/-/,$_[0]))[-1];


    # TODO rewrite general get zone list to search
    # need to cover 204 no content to be working for checkZone()
    # my $hash = (split(/-/,$_[0]))[-1];
    # $client->GET("/agapi/v1/ddos/zone/?search=".$hash);

    #current working aproach
    #
    $client->GET("/agapi/v1/ddos/zone/?count=1000");
  }
  if ($client->responseCode() eq '200') {
    my $zone_tmp = decode_json($client->responseContent());

    return $zone_tmp
  } else {
    if ($return ne 'fail') {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Cannot obtain the list of zones. Error: ".$$json_hash_ref{'message'}."\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
    }
  }
  # in case of failure
  return 0;
}

#------------------------------------------------------------------------------------------------
# Function to check if there is a zone
# string $zone_name Name of the zone we want to create and check if it does arelady exist
# return 0 name exist, 1 it does not
sub checkZone {
  my $retval = 1;
  my ($zone_name) = @_;
  my $orig_name;

  foreach my $zone (@{$zones}) {
    # Verify if there is a matching name
    my $tmp_name = $$zone{"zone_name"};
    $orig_name = $$zone{"zone_name"};
    $tmp_name = (split('-',$tmp_name))[-1];
    my $zone_name_tmp = (split('-',$zone_name))[-1];
    if ($debug){
	    print {$fh} localtime() . " DEBUG: tmp_name: ".$tmp_name." zone_name_tmp: ".$zone_name_tmp."\n";
    }
    if ($tmp_name eq $zone_name_tmp) {
      #the name does exist
      $retval = 0;
      $orig_name = $$zone{"zone_name"};
      if ($debug) {
        print {$fh} localtime() . " DEBUG: The zone name ".$zone_name." does already exist!\n";
      }
      return $retval;
    }
  }
  # name does not exists
  if ($debug) {
      print {$fh} localtime() . " DEBUG: The zone name ".$zone_name." does not exists. \n";
  }
  return ($retval, $orig_name);

} # end checkZone()

#-----------------------------------------------------------------------------------------
# To check the zone does not contain specific IP
# return 0 - there is overlap with IP, 1 there is not overlap
# also return array where new configuration overlaps with some segment we want to configure
sub checkIP {
  my $retval = 0;
  my ($segment) = @_;

  $client->GET("/agapi/v1/ddos/zone/?ip=".$segment."&fields=zone_name,ip_list");

  if ($client->responseCode() eq '204') {
    # OK IP doesn't exist in some other segment
    return 1;
  }
  elsif ($client->responseCode() eq '200') {
    # IP exists in some other segment
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " WARNING: Segment " .$segment. " already configured in zone ". $$json_hash_ref[0]{'zone_name'} .".\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
    return 0;
  }


  if ($debug) {
    print {$fh} localtime() . " DEBUG: IP - Some other trouble: " .$client->responseContent()."\n";
  }
} # end checkIPs()

# Function for connection to attack DB
sub connectDB {
  my $dbopen = DBI->connect($dsn, $userid, $pass, { RaiseError=>1,PrintError=>1})
          or print {$fh} localtime() . " ERROR: AttackDB - Unable to connect to database.\n";
  if ($debug) {
    print {$fh} localtime() . " DEBUG: AttackDB - Opened connection to database successfully.\n";
  }

  # Check if the attackDB is already created (file has size 0), if not make a new one & store in attacks.db file
  my $dbsize = -s $database;
    if(($dbsize) eq 0) {

  my $query = qq(CREATE TABLE a10 (id INTEGER PRIMARY KEY AUTOINCREMENT, attackid INT NOT NULL, zonename TEXT, type TEXT););
  my $rv = $dbopen->do($query);

  if($rv < 0){
    print $DBI::errstr;
  } else {
    if ($debug) {
      print {$fh} localtime() . " DEBUG: AttackDB - Table structure for attacks was created successfully.\n";
    }
  }
  } else {
    if ($debug) {
      print {$fh} localtime() . " DEBUG: AttackDB - Database is already created.\n";
    }
  }
  return $dbopen;
}

# Function for disconnection from attack DB
sub disconnectDB {
  $dbh->disconnect();
  if ($debug) {
    print {$fh} localtime() . " DEBUG: AttackDB - Disconnected from database successfully.\n";
  }
  return;
}

# Function to check attackDB entries and delete them from attackDB aGalaxy before another activity starts, if any TPS entry found in dual mode subrutine is ended
sub checkDB {

  # Execute this part only, if dual mode is turned on (value == 1 in aGalaxy config file)
  if ($get_mode) {
    my $tpsentry = $dbh->selectrow_array("SELECT COUNT(id) FROM a10 WHERE type = 'TPS'");
    print {$fh} localtime() . " INFO: AttackDB - Number of current TPS type entries in the attack database: " . $tpsentry . "\n";
    if ($tpsentry gt 0){
      return;
    }
  }
  
  # aGalaxy part to be processed and deleted aGalaxy entries only
  my $infoattack = zoneName($$decoded{'segment'}, $$decoded{'attackId'});
  my $itemdb = $dbh->selectrow_array("SELECT COUNT(id) FROM a10 WHERE type = 'aGalaxy'");

  # get number of entries in attack DB
  print {$fh} localtime() . " AttackDB: Number of current aGalaxy type entries in the attack database: " . $itemdb . "\n";

  # Deleting attacks from attackDB for aGalaxy in case any entry in DB has been found
  while ($itemdb > 0){
    my $delattack = $dbh->selectrow_array("SELECT zonename FROM a10 ORDER BY id DESC LIMIT 1");
    my $delattackid = $dbh->selectrow_array("SELECT attackid FROM a10 ORDER BY id DESC LIMIT 1");
    print {$fh} localtime() . " AttackDB: Deleting found attack item: ". $delattack . "\n";

    # Delete zone from aGalaxy appliance
    deleteZone($delattack, $delattackid);

    # Delete previously unsuccessful attack from database
    my $delquery = qq(DELETE FROM a10 WHERE zonename = "$delattack";);
    my $return_value = $dbh->do($delquery) or print {$fh} localtime() . " DEBUG: Unable to delete entry from attackDB. " . $DBI::errstr . "\n";
    $itemdb--;
  }
  return;
}

# Function to store an attack information to attackDB in case of unsuccessfull connection to the aGalaxy appliance
# Added type option stored into DB
sub storeDB {
  my $attackinfo = zoneName($$decoded{'segment'}, $$decoded{'attackId'});
  my $stmt = qq(INSERT INTO A10 (ATTACKID,ZONENAME,TYPE) VALUES ($$decoded{'attackId'}, "$attackinfo", 'aGalaxy'));
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " AttackDB: Unable to write aGalaxy attack entry in database.\n " . $DBI::errstr;

  if ($debug) {
    print {$fh} localtime() . " AttackDB: aGalaxy information for $attackinfo has been stored into database successfully.\n";
  }
  return;
}


