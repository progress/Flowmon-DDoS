#!/usr/bin/perl
# Script to provide configuratrion to A10 Thunder TPS appliance version 3.2.2
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>, Jiri Krejcir <jiri.krejcir@flowmon.com>
# Version: 3.5

package a10TPSclient;
use strict;
use warnings;
use Exporter;
use REST::Client;
use Digest::MD5 qw(md5_hex);
use JSON;
use HTTP::Request::Common;
use Net::SSL; 
use Net::IP qw(ip_get_version ip_expand_address ip_iptobin ip_bintoip);
use POSIX qw(strftime);
use Math::Round;
# Added DBI module for SQLite support
use DBI;
use 5.010;

require '/data/components/a10tps/etc/a10config.pl';
my $username = get_user();
my $password = get_password();
my $ip = get_ip();
my $debug = get_debug();
my $advertised = get_advertised();
my $client = undef;
my $get_mode = get_mode();


# database configuration
# install "libdbd-sqlite3-perl" package to support SQLite DB
my $driver = "SQLite";
my $database = "/data/components/agalaxyclient/etc/attacks.db";
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $pass = "";
my $dbh = "";

# Here we take the only argument of script which is filename where is stored
# the detail of attack in JSON format
my ($iad_parametres_file) = $ARGV[0];
my ($template) = $ARGV[1] || "Flowmon_zone_template";

# Load the details into the string
open (FILE, $iad_parametres_file) or die "Couldn't open file: $!";
binmode FILE;
my $iad_params = <FILE>;
close FILE;
open (my $fh, ">>", "/data/components/a10tps/log/tps-communication.log"); 

if ($get_mode){
  # Open connection into attackDB
  $dbh = connectDB();
}

my $decoded = decode_json($iad_params);
my $zones;
                        
if (not defined $iad_parametres_file) {
  print {$fh} localtime() . " FATAL: Parameter with attack not passed from the script!\n";
  die "Fatal: Parametre not passed form the script, exiting";
}

# Login into the appliance and set up needed token
my $return = clientLogin();

if ( $template eq "install" ) {
  install();
}
else {
  $zones = getZones();
  # Attack started we will need to configure a device
  if ($$decoded{'event'} eq 'statistics') {
    print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " detected, attack signature: ".$$decoded{'attacksignature'}."\n";
    
    # Generate unique segment name
    my $name = zoneName($$decoded{'segment'}, $$decoded{'attackId'});
    
    my ($exist, $orig) = checkZone($name);
    # When dual mode is active continue to make a new profile on the TPS appliance
    if ($exist) {
      # first we create DOS profile
      createZone($name);
      if ($get_mode){
        # write entry into attack database
        storeDB();
      }
    } else {
      # zone exists, do we need to modify it?
      print {$fh} localtime() . " INFO: The zone already exist, no configuration applied.\n";
    }
      
    print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
  }
  # Attack is over so it's time to remove the config from device
  elsif ($$decoded{'event'} eq 'ended') {
    print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
    print {$fh} localtime() . " INFO: Deleting profiles from appliance\n";
    
    # Generate unique segment name       
    deleteZone(zoneName($$decoded{'segment'}, $$decoded{'attackId'}));
    # Delete entry from attackDB, if dual mode is active
    if ($get_mode){
        # delete entry from the attack database
        my $delattack = $dbh->selectrow_array("SELECT zonename FROM a10 WHERE type = 'TPS' ORDER BY id DESC LIMIT 1");
        my $delquery = qq(DELETE FROM a10 WHERE zonename = "$delattack");
        my $return_value = $dbh->do($delquery) or print {$fh} localtime() . " ERROR: AttackDB - Unable to delete TPS entry from the attackDB. " . $DBI::errstr . "\n";
        
      }
  } else {
    print {$fh} localtime() . " INFO: Unconfigured action detectected, exiting.\n";  
  }
}
$return = clientLogoff();

###################################################################################
# General Function

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

        return undef unless ($ipversion = ip_get_version($ip));
        return undef unless ($ip = ip_expand_address($ip, $ipversion));
        return undef unless ($curr_bin = ip_iptobin($ip, $ipversion));
        if (defined $len) {
            return undef unless ($len =~ s!^/(\d+)(\,|$)!!);
            $len = $1;

            return undef if ($len > 128);
            return undef if (($len > 32) && ($ipversion == 4));

            $rest = substr($curr_bin, $len);
            $rest =~ s/1/0/g;
            substr($curr_bin, $len) = $rest;

            $retval = ip_bintoip($curr_bin, $ipversion) . "/" . $len;
        } else {
            $retval = $ip;
        }
    }
} # end ipAddressNormalize()

# Function to work on array to get out unwatned keys.
sub process_hash {
    my $ref = shift();

    foreach my $key (keys %{$ref}) {
      if ($key eq 'uuid') {
        delete($$ref{$key});
      }
      elsif ($key eq 'a10-url') {
        delete($$ref{$key});
      }
      elsif ($key eq 'zone-threshold-num')
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
# Function to login into the TPS in order to be able to start commanding it
# no parametres are required here
sub clientLogin {

    my $retval;

    $client = REST::Client->new();
    $client->getUseragent()->ssl_opts( 'verify_hostname' => 0 );
    $client->setHost('https://'.$ip);
    $client->addHeader('Content-Type', 'application/json');

    $client->POST('/axapi/v3/auth', '{"credentials": {"username": "'.$username.'", "password": "'.$password.'"}}');

    if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " INFO: Connected to TPS " .$ip. " successfully.\n";
        $retval = $client->responseCode();
        my $json_hash_ref = decode_json($client->responseContent());
        
        $client->addHeader('Authorization', 'A10 '.$$json_hash_ref{'authresponse'}{'signature'});

        return 0;
    } else {
        $retval = $client->responseCode();
        
        if ($client->responseContent() =~ m/forbidden/) {
            print {$fh} localtime() . " ERROR: Authentication to TPS " .$ip. " failed.\n";
            $retval = "authentication";
        }
        elsif ($client->responseCode() eq '500') {            
            print {$fh} localtime() . " ERROR: Connection to TPS " .$ip. " failed. No such host.\n";
            $retval = "host";
        } else {
            print {$fh} localtime() . " ERROR: Connection to TPS " .$ip. " failed. General error.\n";
            $retval = "generic";
        }
    }

    return $retval;
} # end clientLogin()

# ----------------------------------------------------------------------
# Function to logg off the client after commands are issuesd
# no params here
sub clientLogoff {
  my $retval;
  
  $client->POST('/axapi/v3/logoff');
  
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Disconnected from TPS " .$ip. " successfully.\n";
    return 0;
  }
  elsif ($client->responseContent() =~ m/forbidden/) {
    print {$fh} localtime() . " ERROR: Logoff from TPS " .$ip. " failed.\n";
    $retval = "authentication";
  }
  elsif ($client->responseCode() eq '500') {            
    print {$fh} localtime() . " ERROR: Connection to TPS " .$ip. " failed. No such host.\n";
     $retval = "host";
  } else {
    print {$fh} localtime() . " ERROR: Connection to TPS " .$ip. " failed. General error.\n";
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
  
  # check if there is a FlowmonTemplate DOS profile on appliance
  $client->GET("/axapi/v3/ddos/dst/zone/" . $template);
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Template " . $template . " exist will use it for zone creation.\n";
    my $zone_template = decode_json($client->responseContent());
    
    $$zone_template{'zone'}{'zone-name'} =  $zone_name;
    $$zone_template{'zone'}{'description'} = "Flowmon DDoS zone for Attack ID ".$$decoded{'attackId'};
    process($zone_template); 

    my @ipv4_list;
    my @ipv6_list;
    
    # We will go through configured subnets and create ip list for all of them
    foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
      my %ipv4_config;
      my %ipv6_config;
      # Parse the IP to get IP and MASK
      my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());

      # let's check if it's IP v4 or v6
      if ($ip_seg->version() == 4)
      {
        # if there is only a host mitigation we will use IP only for a profile
        if ($ip_seg->prefixlen() == 32) {
           $subnet = $ip_seg->ip();
           %ipv4_config = ("ip-addr" => $subnet);
        }
        else {
          %ipv4_config = ("subnet-ip-addr" => $subnet);  
        }
        push(@ipv4_list, \%ipv4_config); 
      }
      else {
        if ($ip_seg->prefixlen() == 128) {
          $subnet = $ip_seg->ip();
          %ipv6_config = ("ip6-addr" => $subnet);
        }
        else {
          %ipv6_config = ("subnet-ipv6-addr" => $subnet);
        }
        push(@ipv6_list, \%ipv6_config); 
      }
    }
    
    # Add IPs to the zone template
    if (@ipv6_list) {
      $$zone_template{'zone'}{"ipv6"} = \@ipv6_list;
    }
    if (@ipv4_list) {
      $$zone_template{'zone'}{"ip"} = \@ipv4_list;
    }
    
    # send profile to appliance to create it                                     
    $client->POST('/axapi/v3/ddos/dst/zone/', encode_json($zone_template));
    
    if ($client->responseCode() eq '200') {
      print {$fh} localtime() . " INFO: Zone " .$zone_name. " successfully created from template " . $template . ".\n"; 
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Zone " .$zone_name. " from template " . $template . " was not created. Message: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
    }   
  } 
  else
  # Template does not exist or was not handed over in parametre so we shall use template for standard attacks
  {
    my @ipv4_list;
    my @ipv6_list;
    
    # We will go through configured subnets and create ip list for all of them
    foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
      my %ipv4_config;
      my %ipv6_config;
      # Parse the IP to get IP and MASK
      my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());

      # let's check if it's IP v4 or v6
      if ($ip_seg->version() == 4)
      {
        # if there is only a host mitigation we will use IP only for a profile
        if ($ip_seg->prefixlen() == 32) {
           $subnet = $ip_seg->ip();
           %ipv4_config = ("ip-addr" => $subnet);
        }
        else {
          %ipv4_config = ("subnet-ip-addr" => $subnet);  
        }
        push(@ipv4_list, \%ipv4_config); 
      }
      else {
        if ($ip_seg->prefixlen() == 128) {
          $subnet = $ip_seg->ip();
          %ipv6_config = ("ip6-addr" => $subnet);
        }
        else {
          %ipv6_config = ("subnet-ipv6-addr" => $subnet);
        }
        push(@ipv6_list, \%ipv6_config); 
      }
    }
    
    my @service_list;
    
    # Service DNS - 53 UDP ##############################################
    my @ind0_53u;
    my @level_list_53u;
    my %list0_53u = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => $$decoded{'pps_dns'} );
    push (@ind0_53u, \%list0_53u);    
    my %level0_53u = ("level-num" => "0",
                  "indicator-list" => \@ind0_53u);
    my @ind1_53u;
    my %list1_53u = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => round($$decoded{'pps_dns'} * 1.1) );
    push (@ind1_53u, \%list1_53u);
    my %zone1_53u = ( "dns" => "DNS_UDP_Intermediate" );
    my %level1_53u = ( "level-num" => "1",
                       "zone-template" => \%zone1_53u,
                       "indicator-list" => \@ind1_53u,
                       "src-escalation-score" => 10);  
    my %zone2_53u = ( "dns" => "DNS_UDP_Advanced" );
    my %level2_53u = ( "level-num" => "2",
                       "zone-template" => \%zone2_53u );
    push (@level_list_53u, \%level0_53u, \%level1_53u, \%level2_53u);   
    my %port_53u_config = ("port-num" => 53,
                          "protocol" => "dns-udp",
                          "deny" => 0,
                          "enable-top-k" => 1,
                          "level-list" => \@level_list_53u );
    # END Service DNS - 53 UDP ###########################################
    
    # Service DNS - 53 TCP ###############################################
    my @ind_53t;
    my @level_list_53t;
   
    my %list0_53t = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => $$decoded{'pps_dns'} );
    push (@ind_53t, \%list0_53t);
    
    my %level0_53t = ("level-num" => "0",
                      "zone-escalation-score" => 10,
                      "indicator-list" => \@ind_53t);
    my %zone1_53t = ( "dns" => "DNS_TCP_Intermediate",
                      "tcp" => "TCP_Intermediate" );
    my %level1_53t = ( "level-num" => "1",
                       "zone-template" => \%zone1_53t );  
    push (@level_list_53t, \%level0_53t, \%level1_53t);  
    my %port_53t_config = ("port-num" => 53,
                          "protocol" => "dns-tcp",
                          "deny" => 0,
                          "enable-top-k" => 1,
                          "level-list" => \@level_list_53t );  
    # END Service DNS - 53 TCP ###########################################
    
    # Service HTTP - 80 TCP ##############################################
    my @ind_80;
    my @level_list_80;
   
    my %list0_80 = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => $$decoded{'pps_http'} );
    push (@ind_80, \%list0_80);    
    my %zone0_80 = ( "http" => "HTTP_Basic" );
    my %level0_80 = ("level-num" => "0",
                      "zone-escalation-score" => 10,
                      "indicator-list" => \@ind_80,
                      "zone-template" => \%zone0_80 );
    my @ind1_80;  
    my %list1_80 = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => round($$decoded{'pps_http'} * 1.1 ) );
    push (@ind1_80, \%list1_80); 
    my %level1_80 = ("level-num" => "1",
                      "zone-escalation-score" => 10,
                      "indicator-list" => \@ind1_80,
                      "zone-template" => \%zone0_80 );
    my @ind2_80;  
    my %list2_80 = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => round($$decoded{'pps_http'} * 1.2 ) );
    push (@ind2_80, \%list2_80); 
    my %zone2_80 = ( "tcp" => "TCP_Intermediate",
                     "http" => "HTTP_Basic");
    my %level2_80 = ("level-num" => "2",
                      "zone-escalation-score" => 10,
                      "indicator-list" => \@ind2_80,
                      "zone-template" => \%zone2_80 ); 
    my @ind3_80;  
    my %list3_80 = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => round($$decoded{'pps_http'} * 1.3 ) );
    push (@ind3_80, \%list3_80); 
    my %zone3_80 = ( "tcp" => "TCP_Intermediate",
                     "http" => "HTTP_Intermediate");
    my %level3_80 = ("level-num" => "3",
                      "indicator-list" => \@ind3_80,
                      "zone-template" => \%zone3_80 ); 
    push (@level_list_80, \%level0_80, \%level1_80, \%level2_80, \%level3_80);  
    my %port_80_config = ("port-num" => 80,
                          "protocol" => "http",
                          "deny" => 0,
                          "enable-top-k" => 1,
                          "level-list" => \@level_list_80 );   
    # END Service HTTP - 80 TCP #########################################
    
    # Service HTTPS - 443 TCP ###########################################
    my @ind_443;
    my @level_list_443;
   
    my %list0_443 = ( "type" => "pkt-rate",
                      "score" => 20,
                      "zone-threshold-num" => $$decoded{'pps_https'} );
    push (@ind_443, \%list0_443);    
    my %level0_443 = ("level-num" => "0",
                      "zone-escalation-score" => 10,
                      "indicator-list" => \@ind_443 );
    my %zone1_443 = ( "tcp" => "TCP_Intermediate",
                      "ssl-l4" => "SSL_L4_Basic" );
    my %level1_443 = ("level-num" => "1",
                      "zone-escalation-score" => 10,
                      "zone-template" => \%zone1_443 ); 
    push (@level_list_443, \%level0_443, \%level1_443);  
    my %port_443_config = ("port-num" => 443,
                          "protocol" => "ssl-l4",
                          "deny" => 0,
                          "enable-top-k" => 1,
                          "level-list" => \@level_list_443 );   
    # END Service HTTPS - 443 TCP ######################################
    
    push (@service_list, \%port_53t_config, \%port_53u_config, \%port_80_config, \%port_443_config);
    
    my @service_other_list;
    my @level_list_tcp;
    my @level_list_udp;
    my @ind_tcp;
    
    my %ind_tcp = ( "zone-threshold-num" => $$decoded{'pps_tcp'},
                    "type" => "pkt-rate",
                    "score" => 20 );
    push (@ind_tcp, \%ind_tcp);
    my %level0_tcp = ( "level-num" => "0",
                       "zone-escalation-score"=> 10,
                       "src-escalation-score" => 10,
                       "indicator-list" => \@ind_tcp );
    my %zone1_tcp = ( "tcp" => "TCP_Intermediate" );
    my %level1_tcp = ( "level-num" => "1",
                       "zone-template"=> \%zone1_tcp );
    push (@level_list_tcp, \%level0_tcp, \%level1_tcp);
    my %item1 = ( "port-other" => "other",
                  "protocol" => "tcp",
                  "deny" => 0,
                  "enable-top-k" => 1,
                  "level-list" => \@level_list_tcp );
    my @ind_udp;
    my %ind_udp = ( "zone-threshold-num" => $$decoded{'pps_udp'},
                    "type" => "pkt-rate",
                    "score" => 20 );
    push (@ind_udp, \%ind_udp);    
    my %level0_udp = ( "level-num" => "0",
                       "zone-escalation-score"=> 10,
                       "indicator-list" => \@ind_udp );
    my %zone1_udp = ( "udp" => "UDP_Intermediate" );
    my %level1_udp = ( "level-num" => "1",
                       "zone-template"=> \%zone1_udp );
    my %item2 = ( "port-other" => "other",
                  "protocol" => "udp",
                  "deny" => 0,
                  "enable-top-k" => 1,
                  "level-list" => \@level_list_udp );
    push (@service_other_list, \%item1, \%item2);
    
    my %port_list = ( "zone-service-list" => \@service_list,
                      "zone-service-other-list" => \@service_other_list);
    
    my @proto_name;    
    my %proto_other = ("protocol" => "other",
                       "deny" => 0,
                       "enable-top-k" => 1,
                       "drop-frag-pkt" => 0 );
    my %proto_ipv6encap = ( "protocol" => "ipv6-encap",
                            "deny" => 0,
                            "tunnel-decap" => 0,
                            "drop-frag-pkt" => 0,
                            "tunnel-rate-limit" => 0,
                            "enable-top-k" => 1 );
    my %proto_ipv4encap = ( "protocol" => "ipv4-encap",
                            "deny" => 0,
                            "tunnel-decap" => 0,
                            "drop-frag-pkt" => 0,
                            "tunnel-rate-limit" => 0,
                            "enable-top-k" => 1 );
    my %proto_icpm6 = ("protocol" => "icmp-v6",
                       "deny" => 1,
                       "enable-top-k" => 1,
                       "drop-frag-pkt" => 0 );
    my @list_icmp4;
    my @ind0_icmp;
    my %ind0_icmp = ( "zone-threshold-num" => $$decoded{'pps_icmp'},
                     "type" => "pkt-rate",
                     "score" => 20 );
    push (@ind0_icmp, \%ind0_icmp);
    my %level0_icmp = ( "level-num" => "0",
                        "zone-escalation-score" => 10,
                        "indicator-list" => \@ind0_icmp );  
    my @ind1_icmp;
    my %ind1_icmp = ( "zone-threshold-num" => $$decoded{'pps_icmp'},
                     "type" => "pkt-rate",
                     "zone-violation-actions" => "Blacklist_Source" );
    push (@ind1_icmp, \%ind1_icmp);
    my %zone1_icmp = ( "icmp-v4" => "ICMP_v4_Basic" );
    my %level1_icmp = ( "level-num" => "1",
                        "zone-template" => \%zone1_icmp,
                        "indicator-list" => \@ind1_icmp );
    push (@list_icmp4, \%level0_icmp);
    my %proto_icpm4 = ("protocol" => "icmp-v4",
                       "deny" => 0,
                       "enable-top-k" => 1,
                       "drop-frag-pkt" => 1,
                       "level-list" => \@list_icmp4);
    my %proto_gre = ( "protocol" => "gre",
                      "deny" => 1,
                      "tunnel-decap" => 0,
                      "drop-frag-pkt" => 0,
                      "tunnel-rate-limit" => 0,
                      "enable-top-k" => 1 );
    
    push (@proto_name, \%proto_other, \%proto_ipv6encap, \%proto_ipv4encap, \%proto_icpm6, \%proto_icpm4, \%proto_gre);
    
    my @proto_number;
    my %proto_2 = ( "deny" => 0,
                    "enable-top-k" => 1,
                    "protocol-num" => 2,
                    "drop-frag-pkt" => 0 );
    push (@proto_number, \%proto_2);
    
    my @proto_list;
    my %proto_list_udp = ( "drop-frag-pkt" => 1,
                           "protocol" => "udp" );
    my %proto_list_tcp = ( "drop-frag-pkt" => 1,
                           "protocol" => "tcp" );
    push (@proto_list, \%proto_list_tcp, \%proto_list_udp);
    
    my %ip_proto = ( "proto-name-list" => \@proto_name,
                     "proto-tcp-udp-list" => \@proto_list,
                     "proto-number-list" => \@proto_number );
    my @src_port;
    my %port_19 = ( "deny" => 1,
                    "port-num" => 19,
                    "protocol" => "udp" );
    my %glid_cfg = ( "glid" => "Strict_Rate_Limit" );
    my %port_53 = ( "deny" => 0,
                    "port-num" => 53,
                    "protocol" => "udp",
                    "glid-cfg" => \%glid_cfg );
    my %port_111 = ( "deny" => 1,
                    "port-num" => 111,
                    "protocol" => "udp" );
    my %port_123 = ( "deny" => 0,
                    "port-num" => 123,
                    "protocol" => "udp",
                    "glid-cfg" => \%glid_cfg );
    my %port_137 = ( "deny" => 1,
                    "port-num" => 137,
                    "protocol" => "udp" );
    my %port_161 = ( "deny" => 1,
                    "port-num" => 161,
                    "protocol" => "udp" );
    my %port_1434 = ( "deny" => 1,
                    "port-num" => 1434,
                    "protocol" => "udp" );
    my %port_1900 = ( "deny" => 1,
                    "port-num" => 1900,
                    "protocol" => "udp" );
    push (@src_port, \%port_19, \%port_53, \%port_111, \%port_123, \%port_137, \%port_161, \%port_1434, \%port_1900);
    my %src_port = ( "zone-src-port-list" => \@src_port );
  
    my %zone = ( "zone-name" => $zone_name,
                 "description" => "Flowmon DDoS zone for Attack ID ".$$decoded{'attackId'},
                 "operational-mode" => "monitor",
                 "advertised-enable" => $advertised,
                 "log-enable" => 1,
                 "log-periodic" => 1,
                 "port" => \%port_list,
                 "ip-proto" => \%ip_proto,
                 "src-port" => \%src_port
                );
    
    # Add IPs to the zone template
    if (@ipv6_list) {
      $zone{"ipv6"} = \@ipv6_list;
    }
    if (@ipv4_list) {
      $zone{"ip"} = \@ipv4_list;
    }
    
    my @zone_hash;
    push(@zone_hash, \%zone);
    my %zone_config = ( "zone" => \@zone_hash);

    $client->POST('/axapi/v3/ddos/dst/zone/', encode_json(\%zone_config));
    
    my $json_hash_ref = decode_json($client->responseContent());
    
    if ($client->responseCode() > '200') {
      $retval = "host";
      print {$fh} localtime() . " INFO: Cannot create a zone $zone_name! Message: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
      if ($debug) {
        print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
      }
    }
    elsif ($client->responseCode() eq '200') {
      print {$fh} localtime() . " INFO: Zone $zone_name created successfully.\n";
      $retval = $client->responseCode();
    } 
  }
  
  return $retval;                
} # end createZone

#-------------------------------------------------------------------------------
# Function to delte the zone from the configuration
# string $zone_name name of zone to be deleted
sub deleteZone { 

  my $retval;
  my ($zone_name) = @_;
  $client->DELETE('/axapi/v3/ddos/dst/zone/'.$zone_name);
  
  my $json_hash_ref = decode_json($client->responseContent());
  
  if ($client->responseCode() > '200') {
    $retval = "host";
    print {$fh} localtime() . " INFO: Cannot delete a zone $zone_name! Message: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  elsif ($client->responseCode() eq '200') { 
    print {$fh} localtime() . " INFO: Zone $zone_name deleted successfully.\n";
    $retval = $client->responseCode();
  }
} # end deleteZone
# ------------------------------------------------------------------------------
# Function to install all required configuration into the A10 TPS box
# no parametres here
sub install {
  print {$fh} localtime() . " INFO: Starting installation procedure to prepare TPS for integration with Flowmon.\n";
  ###############################################################################
  # Create GLID
  print {$fh} localtime() . " INFO: Creating GLID Strict_Rate_Limit.\n";
  my %glid = ( "name" => "Strict_Rate_Limit",
               "description" => "Apply to objects with expected low PPS",
               "pkt-rate-limit" => "1000" );
  my @glid_arr;
  push (@glid_arr, \%glid);
  my %glid_config = ( "glid" => \@glid_arr );
  # send GLID to appliance to create it                                     
  $client->POST('/axapi/v3/glid/', encode_json(\%glid_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: GLID Strict_Rate_Limit successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: GLID Strict_Rate_Limit was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  #############################################################################
  # Create zone tempates for protections
  print {$fh} localtime() . " INFO: Creating required zone-templates.\n";
  my %type0_rate = ( "dst-type-rate" => 100 );
  my %type0 = ( "type-number" => 0,
                "v4-dst-rate-cfg" => \%type0_rate );
  my %type5 = ( "type-number" => 5 );
  my %type8 = ( "type-number" => 8 );
  my %type9 = ( "type-number" => 9 );
  my %type10 = ( "type-number" => 10 );
  my %type11 = ( "type-number" => 11 );
  my %type14 = ( "type-number" => 14 );
  my @icmp_type;
  push (@icmp_type, \%type0, \%type5, \%type8, \%type9, \%type10, \%type11, \%type14);
  my %icmp = ( "icmp-tmpl-name" => "ICMP_v4_Basic",
               "type-list" => \@icmp_type );
  my @icmpv4_arr;
  push ( @icmpv4_arr, \%icmp );
  my %icmp_config = ( "icmp-v4" => \@icmpv4_arr );
  # send ICMP template to appliance to create it                                     
  $client->POST('/axapi/v3/ddos/zone-template/icmp-v4/', encode_json(\%icmp_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone template ICMP_v4_Basic successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template ICMP_v4_Basic was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  ########################
  my %dst_t_i = ( "rate-limit" => { "request" => { "type" => {
                  "A-cfg" => { "A" => 1, "dns-a-rate" => 50000 },
                  "AAAA-cfg" => { "AAAA" => 1, "dns-aaaa-rate" => 1000 },
                  "MX-cfg" => { "MX" => 1, "dns-mx-rate" => 1000 },
                  "NS-cfg" => { "NS" => 1, "dns-ns-rate" => 1000 }
                } } } );
  my %mal_query = ( "validation-type" => "extended-header-check" );
  my %dns_t_i = ( "name" => "DNS_TCP_Intermediate",
                  "dns-any-check" => 1,
                  "dst" => \%dst_t_i,
                  "malformed-query-check" => \%mal_query );
  my %dns_u_i = ( "name" => "DNS_UDP_Intermediate",
                  "dns-any-check" => 1,
                  "dst" => \%dst_t_i,
                  "malformed-query-check" => \%mal_query,
                  "dns-udp-authentication" => { "udp-timeout" => 5, "min-delay" => 3 } );
  my %dns_u_a = ( "name" => "DNS_UDP_Advanced",
                  "dns-any-check" => 1,
                  "dst" => \%dst_t_i,
                  "malformed-query-check" => \%mal_query,
                  "dns-udp-authentication" => { "force-tcp-cfg" => { "force-tcp" => 1 } } );
  my @dns_list;
  push (@dns_list, \%dns_t_i, \%dns_u_i, \%dns_u_a);
  my %dns_config = ( "dns-list" => \@dns_list );
  # send DNS template to appliance to create it
  $client->POST('/axapi/v3/ddos/zone-template/dns/', encode_json(\%dns_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone template for DNS successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for DNS was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
  }
  ######################
  my %tcp_conf = ( "name" => "TCP_Intermediate",
                   "zero-win-cfg" => { "zero-win" => 16, "zero-win-action" => "drop" },
                   "syn-authentication" => { "syn-auth-type" => "send-rst", "syn-auth-rto" => 0 },
                   "ack-authentication" => { "ack-auth-timeout" => 3, "ack-auth-min-delay" => 1 }
                 );
  my %tcp_config = ( "tcp" => \%tcp_conf );
  # send TCP template to appliance to create it
  $client->POST('/axapi/v3/ddos/zone-template/tcp/', encode_json(\%tcp_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone template for TCP successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for TCP was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
  }
  ####################
  my %udp_conf = ( "name" => "UDP_Intermediate",
                   "spoof-detect-retry-timeout" => 5 );
  my %udp_config = ( "udp" => \%udp_conf );
  # send UDP template to appliance to create it
  $client->POST('/axapi/v3/ddos/zone-template/udp/', encode_json(\%udp_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone template for UDP successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for UDP was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
  }
  ####################
  my %ssl_conf = ( "ssl-l4-tmpl-name" => "SSL_L4_Basic",
                   "renegotiation" => { "num-renegotiation" => 4 } );
  my %ssl_config = ( "ssl-l4" => \%ssl_conf );
  # send SSL template to appliance to create it
  $client->POST('/axapi/v3/ddos/zone-template/ssl-l4/', encode_json(\%ssl_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone template for SSL successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for SSL was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
  }
  ########################
  my %http_b = ( "http-tmpl-name" => "HTTP_Basic",
                 "mss-timeout" => { "mss-percent" => 25, "number-packets" => 5 },
                 "slow-read" => { "min-window-size" => 1024, "min-window-count" => 15 },
                 "malformed-http" => { "malformed-http" => "check" } );
  my %http_i = ( "http-tmpl-name" => "HTTP_Intermediate",
                 "mss-timeout" => { "mss-percent" => 25, "number-packets" => 5 },
                 "slow-read" => { "min-window-size" => 1024, "min-window-count" => 15 },
                 "malformed-http" => { "malformed-http" => "check" },
                 "challenge" => { "challenge-method" => "http-redirect" } );
  my @http_list;
  push (@http_list, \%http_b, \%http_i);
  my %http_config = ( "http-list" => \@http_list );
  # send DNS template to appliance to create it
  $client->POST('/axapi/v3/ddos/zone-template/http/', encode_json(\%http_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone template for HTTP successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Zone template for HTTP was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  ####################
  my %violation_conf = ( "name" => "Blacklist_Source",
                         "blacklist-src" => 5 );
  my %violation_config = ( "violation-actions" => \%violation_conf );
  # send Blacklist template to appliance to create it
  $client->POST('/axapi/v3/ddos/violation-actions/', encode_json(\%violation_config));
    
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Violation action Blacklist successfully created.\n"; 
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Violation action Blacklist was not created. Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
    
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  
  #####################################################
  # Now lets create zone template
  my @service_list;
    
  # Service DNS - 53 UDP ##############################################
  my @ind0_53u;
  my @level_list_53u;
  my %list0_53u = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110205100 );
  push (@ind0_53u, \%list0_53u);    
  my %level0_53u = ("level-num" => "0",
                "indicator-list" => \@ind0_53u);
  my @ind1_53u;
  my %list1_53u = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110205110 );
  push (@ind1_53u, \%list1_53u);
  my %zone1_53u = ( "dns" => "DNS_UDP_Intermediate" );
  my %level1_53u = ( "level-num" => "1",
                     "zone-template" => \%zone1_53u,
                     "indicator-list" => \@ind1_53u,
                     "src-escalation-score" => 10);  
  my %zone2_53u = ( "dns" => "DNS_UDP_Advanced" );
  my %level2_53u = ( "level-num" => "2",
                     "zone-template" => \%zone2_53u );
  push (@level_list_53u, \%level0_53u, \%level1_53u, \%level2_53u);   
  my %port_53u_config = ("port-num" => 53,
                        "protocol" => "dns-udp",
                        "deny" => 0,
                        "enable-top-k" => 1,
                        "level-list" => \@level_list_53u );
  # END Service DNS - 53 UDP ###########################################
  
  # Service DNS - 53 TCP ###############################################
  my @ind_53t;
  my @level_list_53t;
 
  my %list0_53t = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110205100 );
  push (@ind_53t, \%list0_53t);
  
  my %level0_53t = ("level-num" => "0",
                    "zone-escalation-score" => 10,
                    "indicator-list" => \@ind_53t);
  my %zone1_53t = ( "dns" => "DNS_TCP_Intermediate",
                    "tcp" => "TCP_Intermediate" );
  my %level1_53t = ( "level-num" => "1",
                     "zone-template" => \%zone1_53t );  
  push (@level_list_53t, \%level0_53t, \%level1_53t);  
  my %port_53t_config = ("port-num" => 53,
                        "protocol" => "dns-tcp",
                        "deny" => 0,
                        "enable-top-k" => 1,
                        "level-list" => \@level_list_53t );  
  # END Service DNS - 53 TCP ###########################################
  
  # Service HTTP - 80 TCP ##############################################
  my @ind_80;
  my @level_list_80;
 
  my %list0_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110204100 );
  push (@ind_80, \%list0_80);    
  my %zone0_80 = ( "http" => "HTTP_Basic" );
  my %level0_80 = ("level-num" => "0",
                    "zone-escalation-score" => 10,
                    "indicator-list" => \@ind_80,
                    "zone-template" => \%zone0_80 );
  my @ind1_80;  
  my %list1_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110204110 );
  push (@ind1_80, \%list1_80); 
  my %level1_80 = ("level-num" => "1",
                    "zone-escalation-score" => 10,
                    "indicator-list" => \@ind1_80,
                    "zone-template" => \%zone0_80 );
  my @ind2_80;  
  my %list2_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110204120 );
  push (@ind2_80, \%list2_80); 
  my %zone2_80 = ( "tcp" => "TCP_Intermediate",
                   "http" => "HTTP_Basic");
  my %level2_80 = ("level-num" => "2",
                    "zone-escalation-score" => 10,
                    "indicator-list" => \@ind2_80,
                    "zone-template" => \%zone2_80 ); 
  my @ind3_80;  
  my %list3_80 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110204130 );
  push (@ind3_80, \%list3_80); 
  my %zone3_80 = ( "tcp" => "TCP_Intermediate",
                   "http" => "HTTP_Intermediate");
  my %level3_80 = ("level-num" => "3",
                    "indicator-list" => \@ind3_80,
                    "zone-template" => \%zone3_80 ); 
  push (@level_list_80, \%level0_80, \%level1_80, \%level2_80, \%level3_80);  
  my %port_80_config = ("port-num" => 80,
                        "protocol" => "http",
                        "deny" => 0,
                        "enable-top-k" => 1,
                        "level-list" => \@level_list_80 );   
  # END Service HTTP - 80 TCP #########################################
  
  # Service HTTPS - 443 TCP ###########################################
  my @ind_443;
  my @level_list_443;
 
  my %list0_443 = ( "type" => "pkt-rate",
                    "score" => 20,
                    "zone-threshold-num" => 2110203100 );
  push (@ind_443, \%list0_443);    
  my %level0_443 = ("level-num" => "0",
                    "zone-escalation-score" => 10,
                    "indicator-list" => \@ind_443 );
  my %zone1_443 = ( "tcp" => "TCP_Intermediate",
                    "ssl-l4" => "SSL_L4_Basic" );
  my %level1_443 = ("level-num" => "1",
                    "zone-escalation-score" => 10,
                    "zone-template" => \%zone1_443 ); 
  push (@level_list_443, \%level0_443, \%level1_443);  
  my %port_443_config = ("port-num" => 443,
                        "protocol" => "ssl-l4",
                        "deny" => 0,
                        "enable-top-k" => 1,
                        "level-list" => \@level_list_443 );   
  # END Service HTTPS - 443 TCP ######################################
  
  push (@service_list, \%port_53t_config, \%port_53u_config, \%port_80_config, \%port_443_config);
  
  my @service_other_list;
  my @level_list_tcp;
  my @level_list_udp;
  my @ind_tcp;
  
  my %ind_tcp = ( "zone-threshold-num" => 2110201100,
                  "type" => "pkt-rate",
                  "score" => 20 );
  push (@ind_tcp, \%ind_tcp);
  my %level0_tcp = ( "level-num" => "0",
                     "zone-escalation-score"=> 10,
                     "src-escalation-score" => 10,
                     "indicator-list" => \@ind_tcp );
  my %zone1_tcp = ( "tcp" => "TCP_Intermediate" );
  my %level1_tcp = ( "level-num" => "1",
                     "zone-template"=> \%zone1_tcp );
  push (@level_list_tcp, \%level0_tcp, \%level1_tcp);
  my %item1 = ( "port-other" => "other",
                "protocol" => "tcp",
                "deny" => 0,
                "enable-top-k" => 1,
                "level-list" => \@level_list_tcp );
  my @ind_udp;
  my %ind_udp = ( "zone-threshold-num" => 2110201100,
                  "type" => "pkt-rate",
                  "score" => 20 );
  push (@ind_udp, \%ind_udp);    
  my %level0_udp = ( "level-num" => "0",
                     "zone-escalation-score"=> 10,
                     "indicator-list" => \@ind_udp );
  my %zone1_udp = ( "udp" => "UDP_Intermediate" );
  my %level1_udp = ( "level-num" => "1",
                     "zone-template"=> \%zone1_udp );
  my %item2 = ( "port-other" => "other",
                "protocol" => "udp",
                "deny" => 0,
                "enable-top-k" => 1,
                "level-list" => \@level_list_udp );
  push (@service_other_list, \%item1, \%item2);
  
  my %port_list = ( "zone-service-list" => \@service_list,
                    "zone-service-other-list" => \@service_other_list);
  
  my @proto_name;    
  my %proto_other = ("protocol" => "other",
                     "deny" => 0,
                     "enable-top-k" => 1,
                     "drop-frag-pkt" => 0 );
  my %proto_ipv6encap = ( "protocol" => "ipv6-encap",
                          "deny" => 0,
                          "tunnel-decap" => 0,
                          "drop-frag-pkt" => 0,
                          "tunnel-rate-limit" => 0,
                          "enable-top-k" => 1 );
  my %proto_ipv4encap = ( "protocol" => "ipv4-encap",
                          "deny" => 0,
                          "tunnel-decap" => 0,
                          "drop-frag-pkt" => 0,
                          "tunnel-rate-limit" => 0,
                          "enable-top-k" => 1 );
  my %proto_icpm6 = ("protocol" => "icmp-v6",
                     "deny" => 1,
                     "enable-top-k" => 1,
                     "drop-frag-pkt" => 0 );
  my @list_icmp4;
  my @ind0_icmp;
  my %ind0_icmp = ( "zone-threshold-num" => 2110206100,
                   "type" => "pkt-rate",
                   "score" => 20 );
  push (@ind0_icmp, \%ind0_icmp);
  my %level0_icmp = ( "level-num" => "0",
                      "zone-escalation-score" => 10,
                      "indicator-list" => \@ind0_icmp );  
  my @ind1_icmp;
  my %ind1_icmp = ( "zone-threshold-num" => 2110206110,
                   "type" => "pkt-rate",
                   "zone-violation-actions" => "Blacklist_Source" );
  push (@ind1_icmp, \%ind1_icmp);
  my %zone1_icmp = ( "icmp-v4" => "ICMP_v4_Basic" );
  my %level1_icmp = ( "level-num" => "1",
                      "zone-template" => \%zone1_icmp,
                      "indicator-list" => \@ind1_icmp );
  push (@list_icmp4, \%level0_icmp);
  my %proto_icpm4 = ("protocol" => "icmp-v4",
                     "deny" => 0,
                     "enable-top-k" => 1,
                     "drop-frag-pkt" => 1,
                     "level-list" => \@list_icmp4);
  my %proto_gre = ( "protocol" => "gre",
                    "deny" => 1,
                    "tunnel-decap" => 0,
                    "drop-frag-pkt" => 0,
                    "tunnel-rate-limit" => 0,
                    "enable-top-k" => 1 );
  
  push (@proto_name, \%proto_other, \%proto_ipv6encap, \%proto_ipv4encap, \%proto_icpm6, \%proto_icpm4, \%proto_gre);
  
  my @proto_number;
  my %proto_2 = ( "deny" => 0,
                  "enable-top-k" => 1,
                  "protocol-num" => 2,
                  "drop-frag-pkt" => 0 );
  push (@proto_number, \%proto_2);
  
  my @proto_list;
  my %proto_list_udp = ( "drop-frag-pkt" => 1,
                         "protocol" => "udp" );
  my %proto_list_tcp = ( "drop-frag-pkt" => 1,
                         "protocol" => "tcp" );
  push (@proto_list, \%proto_list_tcp, \%proto_list_udp);
  
  my %ip_proto = ( "proto-name-list" => \@proto_name,
                   "proto-tcp-udp-list" => \@proto_list,
                   "proto-number-list" => \@proto_number );
  my @src_port;
  my %port_19 = ( "deny" => 1,
                  "port-num" => 19,
                  "protocol" => "udp" );
  my %glid_cfg = ( "glid" => "Strict_Rate_Limit" );
  my %port_53 = ( "deny" => 0,
                  "port-num" => 53,
                  "protocol" => "udp",
                  "glid-cfg" => \%glid_cfg );
  my %port_111 = ( "deny" => 1,
                  "port-num" => 111,
                  "protocol" => "udp" );
  my %port_123 = ( "deny" => 0,
                  "port-num" => 123,
                  "protocol" => "udp",
                  "glid-cfg" => \%glid_cfg );
  my %port_137 = ( "deny" => 1,
                  "port-num" => 137,
                  "protocol" => "udp" );
  my %port_161 = ( "deny" => 1,
                  "port-num" => 161,
                  "protocol" => "udp" );
  my %port_1434 = ( "deny" => 1,
                  "port-num" => 1434,
                  "protocol" => "udp" );
  my %port_1900 = ( "deny" => 1,
                  "port-num" => 1900,
                  "protocol" => "udp" );
  push (@src_port, \%port_19, \%port_53, \%port_111, \%port_123, \%port_137, \%port_161, \%port_1434, \%port_1900);
  my %src_port = ( "zone-src-port-list" => \@src_port );

  my %zone = ( "zone-name" => "Flowmon_zone_template",
               "description" => "Zone template for Flowmon DDoS Defender. !!!DO NOT DELETE!!!",
               "operational-mode" => "monitor",
               "advertised-enable" => $advertised,
               "log-enable" => 1,
               "log-periodic" => 1,
               "port" => \%port_list,
               "ip-proto" => \%ip_proto,
               "src-port" => \%src_port
              );
  my @zone_hash;
  push(@zone_hash, \%zone);
  my %zone_config = ( "zone" => \@zone_hash);

  $client->POST('/axapi/v3/ddos/dst/zone/', encode_json(\%zone_config));
  
  my $json_hash_ref = decode_json($client->responseContent());
  
  if ($client->responseCode() > '200') {
    print {$fh} localtime() . " INFO: Cannot create a zone Flowmon_zone_template! Message: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
    
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  elsif ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Zone Flowmon_zone_template created successfully.\n";
  }
} # end install()#------------------------------------------------------------------------------------------------
# Function to get all zones
# return reference to result
sub getZones {
  # Get the list of all zones to see if there is one which matches
  $client->GET("/axapi/v3/ddos/dst/zone/?count=1000");
  if ($client->responseCode() eq '200') {
    my $zone_tmp = decode_json($client->responseContent());
    return $zone_tmp;
  } 
  elsif ($client->responseCode() eq '204') {
    print {$fh} localtime() . "INFO: No zones on A10 TPS\n";
    return 0;
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Cannot obtain the list of zones. Error: ".$$json_hash_ref{'message'}."\n";
      
    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
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
  my ($z_name) = @_;
  my $orig_name;
  my $retval = 1;
  
  my %zones_hash = %{$zones};
  foreach my $one_zone (@{$zones_hash{'zone-list'}}) {
    # Verify if there is a matching name
    my $tmp_name = $$one_zone{"zone-name"};
    $orig_name = $$one_zone{"zone-name"};
    $tmp_name = (split('-',$tmp_name))[-1];
    my $zone_name_tmp = (split('-',$z_name))[-1];
    if ($tmp_name eq $zone_name_tmp) {
      #the name does exist
      $retval = 0;
      $orig_name = $$one_zone{"zone-name"};
      if ($debug) {
        print {$fh} localtime() . " DEBUG: The zone name ".$z_name." does already exists!\n";
      }
      return ($retval, $orig_name);
    }   
  }
  # name does not exists
  if ($debug) {
      print {$fh} localtime() . " DEBUG: The zone name ".$z_name." does not exists. \n";
  }
  return ($retval, $orig_name);
  
} # end checkZone()

# Function to store an attack information to attackDB in case of unsuccessfull connection to the aGalaxy appliance
# Added type option stored into DB
sub storeDB {
  my $attackinfo = zoneName($$decoded{'segment'}, $$decoded{'attackId'});
  my $stmt = qq(INSERT INTO A10 (ATTACKID,ZONENAME,TYPE) VALUES ($$decoded{'attackId'}, "$attackinfo", 'TPS'));
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: AttackDB - Unable to write TPS attack entry in database.\n " . $DBI::errstr;

  if ($debug) {
    print {$fh} localtime() . " DEBUG: AttackDB - TPS attack information for $attackinfo has been stored into database successfully.\n";
  }
  return;
}

# Function for connection to attack DB
sub connectDB {
  my $dbopen = DBI->connect($dsn, $userid, $pass, { RaiseError=>1,PrintError=>1})
          or print {$fh} localtime() . " ERROR: AttackDB - Unable to connect to database.\n";
  if ($debug) {
    print {$fh} localtime() . " INFO: AttackDB - Opened connection to database successfully.\n";
  }

  # Check if the attackDB is already created (file has size 0), if not make a new one & store in attacks.db file
  my $dbsize = -s $database;
    if(($dbsize) eq 0) {

  my $query = qq(CREATE TABLE A10 (ID INTEGER PRIMARY KEY AUTOINCREMENT, ATTACKID INT NOT NULL, ZONENAME TEXT, TYPE TEXT););
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