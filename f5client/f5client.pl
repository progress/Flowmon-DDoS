#! /usr/bin/perl -w
# Script to configure F5 BIG-IP appliance, tested to work on v12 and v13
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>
# Version: 3.0

package f5Client;

use strict;
use Exporter;
use Data::Dump qw(dump);
use REST::Client;
use JSON;
use HTTP::Request::Common;
use Net::SSL;
use Net::IP;
use Net::IP qw(ip_get_version ip_expand_address ip_iptobin ip_bintoip);
use POSIX qw(strftime);
use Math::Round;

# Username and password for the appliance
my $username = 'admin';
my $password = 'admin';
my $ip = '192.168.47.20';
my $client = undef;
my $ip_seg = undef;
my $blacklist_category = '/Common/denial_of_service '; # name of Blacklist category
my $ip_intelligence = '/Common/ip-intelligence'; # IP Inteligence name

# Here we take the only argument of script which is filename where is stored
# the detail of attack in JSON format
my ($iad_parametres_file) = $ARGV[0];
my ($template) = $ARGV[1] || "FlowmonTemplate"; 

if (not defined $iad_parametres_file) {
  die "Fatal: Parametre not passed form the script, exiting";
}

# Load the details into the string
open (FILE, $iad_parametres_file) or die "Couldn't open file: $!";
binmode FILE;
my $iad_params = <FILE>;
close FILE;
open (my $fh, ">>", "/tmp/iad.log");

my $decoded = decode_json($iad_params);

# Login into the appliance and set up needed token
my $return = clientLogin();

# Attack started we will need to configure a device
if ($$decoded{'event'} eq 'statistics') {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " detected, attack signature: ".$$decoded{'attacksignature'}."\n";
  
  # We will go through configured subnets and create profiles for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    # Parse the IP to get IP and MASK
    $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());
    # Generate unique segment name
    my $vs_name = $$decoded{'segment'} ."_".$$decoded{'attackId'}."_".$ip_seg->hexip(); 
    
    # first we create DOS profile
    print {$fh} localtime() . " INFO: Creating dos profile for subnet ".$subnet."\n";
    createDP($vs_name, $$decoded{'attackId'}, $template);
    
    # then create the virtual switch configuration on appliance    
    print {$fh} localtime() . " INFO: Creating virtual server for subnet ".$subnet."\n";
    createVS($vs_name, $ip_seg->ip(), $ip_seg->mask(), $$decoded{'attackId'});
  }
  print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
}
# Attack is over so it's time to remove the config from device
elsif ($$decoded{'event'} eq 'ended') {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
  print {$fh} localtime() . " INFO: Deleting profiles from appliance\n";
  
  # We will go through configured subnets and delete profiles for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    # Parse the IP to get IP and MASK
    $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());
    # Generate unique segment name
    my $vs_name = $$decoded{'segment'} ."_".$$decoded{'attackId'}."_".$ip_seg->hexip(); 
     
    deleteVS($vs_name);
    deleteDP($vs_name);
  }
}
else {  
  print {$fh} localtime() . " INFO: Unconfigured event type: ".$$decoded{'event'}." detected in file ".$iad_parametres_file."\n";  
  print {$fh} localtime() . " ERROR: F5 appliance could not be configured!\n";
}

###################################################################################
# General Function

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


################################################################################
# REST functions
#

#-------------------------------------------------------------------------------
# Function to connect to device 
# no parametres required here
sub clientLogin {

    my $retval;

    $client = REST::Client->new();
    $client->getUseragent()->ssl_opts( 'verify_hostname' => 0 );
    $client->setHost('https://'.$ip);
    $client->addHeader('Content-Type', 'application/json');

    $client->POST('/mgmt/shared/authn/login', '{"username":"'.$username.'","password":"'.$password.'", "loginProviderName":"tmos"}');
    if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " INFO: Connected to BIG-IP " .$ip. " successfully.\n";
        $retval = $client->responseCode();
        my $json_hash_ref = decode_json($client->responseContent());
        # Add atuhentication token to header to perform additional actions
        $client->addHeader('X-F5-Auth-Token', $$json_hash_ref{'token'}{'token'});

        return 0;
    } else {
        $retval = $client->responseCode();

        if ($client->responseContent() =~ m/Authentication failed./) {
            print {$fh} localtime() . " ERROR: Authentication to BIG-IP " .$ip. " failed.\n";
            $retval = "authentication";
        }
        elsif ($client->responseCode() eq '500') {
            $retval = "host";
        } else {
            $retval = "generic";
        }
    }

    return $retval;
} # end clientLogin()

#-------------------------------------------------------------------------------
# Fuction to create Virtual Server profile
# requres following parametres
# string $vs_name name of virtual server
# string $subnet subnet part of protected segment
# string $mask subnet mask of protected segment
# int $attack_id attack ID from DDoS Defender
sub createVS {
  my ($vs_name, $subnet, $mask, $attack_id) = @_;
  
  my @profiles;
  my %profile = ("name" => "fastL4");
  my %dos = ("name" => "dos_".$vs_name);
  push (@profiles, \%profile, \%dos);
  
  my %virtual_server = ("name" => $vs_name,
                      "destination" => "/Common/".$subnet . ":0",
                      "mask" => $mask,
                      "description" => "Flowmon DDoS Attack ID ".$attack_id,
                      "source" => "0.0.0.0/0",
                      "ipForward" => JSON::true,
                      "ipProtocol" => "any",
                      "ipIntelligencePolicy" => $ip_intelligence,
                      "profiles" => \@profiles);
  
  #IP v6 support
  if ($ip_seg->version() == 6) {
       $virtual_server{"source"} = "::/0",
        $virtual_server{"destination"} = "/Common/". $subnet . ".0",
  }

                      
  # send profile to appliance to create it                                     
  $client->POST('/mgmt/tm/ltm/virtual', encode_json(\%virtual_server));
  
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Profile " .$vs_name. " successfully created.\n";  
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Profile " .$vs_name. " was not created. Error: ".$$json_hash_ref{'message'}."\n";
  }                   
} # end createVS($vs_name, $subnet, $mask, $attack_id)

#-------------------------------------------------------------------------------
# Function to delete Virtual Server profile
# string $vs_name name of profile to delete
sub deleteVS {
  my ($vs_name) = @_;
  
  $client->DELETE('/mgmt/tm/ltm/virtual/'.$vs_name);
  
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Virtual server profile " .$vs_name. " successfully deleted.\n";  
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Profile " .$vs_name. " was not deleted. Error: ".$$json_hash_ref{'message'}."\n";
  } 
} # end deleteVS($vs_name)

#-------------------------------------------------------------------------------
# Function to create DOS profile
# string $vs_name name of Virtual Server
# int $attack_id ID of attack from DDOS Defender
sub createDP {
  my ($vs_name, $attack_id, $template) = @_;
  my %dos_profile;
  $vs_name = "dos_".$vs_name;
  
  # check if there is a FlowmonTemplate DOS profile on appliance
  $client->GET("/mgmt/tm/security/dos/profile/" . $template . "?expandSubcollections=true");
  if ($client->responseCode() eq '200') {
  # if it does exist then we use it for configuration
    print {$fh} localtime() . " INFO: Template " . $template . " exist will use it for profile creation.\n";
    my $dos_profile = decode_json($client->responseContent());
    $$dos_profile{'name'} =  $vs_name;
    $$dos_profile{'description'} = "Flowmon DDoS dos profile for Attack ID ".$attack_id;
    delete $$dos_profile{'selfLink'};
    delete $$dos_profile{'fullPath'}; 
    delete $$dos_profile{'protocolSipReference'}{'link'};
    delete $$dos_profile{'protocolDnsReference'}{'link'}; 
    delete $$dos_profile{'dosNetworkReference'}{'link'}; 
    delete $$dos_profile{'dosNetworkReference'}{'items'}[0]{'selfLink'};
    delete $$dos_profile{'dosNetworkReference'}{'items'}[0]{'fullPath'};
    $$dos_profile{'dosNetworkReference'}{'name'} = $vs_name;
    $$dos_profile{'dosNetworkReference'}{'items'}[0]{'name'} = $vs_name;
    
    # send profile to appliance to create it                                     
    $client->POST('/mgmt/tm/security/dos/profile', encode_json($dos_profile));
    
    if ($client->responseCode() eq '200') {
      print {$fh} localtime() . " INFO: Profile " .$vs_name. " successfully created from template " . $template . ".\n"; 
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Profile " .$vs_name. " from template " . $template . " was not created. Error: ".$$json_hash_ref{'message'}."\n";
    }   
  } else {
  # Template profile does not exist so we create our own
    my @attack_vectors;
    my @ip_methods = ("ext-hdr-too-large", "hop-cnt-low", "host-unreachable", "ip-frag-flood", "ip-low-ttl", "ip-opt-frames", "ipv6-ext-hdr-frames", "ipv6-frag-flood", "opt-present-with-illegal-len", "tidcmp", "too-many-ext-hdrs" );
    my @icmp_methods = ("icmp-frag", "icmpv4-flood", "icmpv6-flood");
    my @tcp_methods = ("tcp-bad-urg", "tcp-opt-overruns-tcp-hdr", "tcp-psh-flood", "tcp-rst-flood", "tcp-syn-flood", "tcp-syn-oversize", "tcp-synack-flood", "tcp-window-size", "unk-tcp-opt-type" );
    my @udp_methods = ("udp-flood");
    my $pps = 10; # we use this value if running baseline has 0 as that is incorrect for F5
    
    foreach my $service (@ip_methods) {
      my %method = ("name" => $service,
                    "rateThreshold" => round(($$decoded{'pps'} ? $$decoded{'pps'} : $pps) * 2),
                    "rateLimit" => round($$decoded{'pps'} ? $$decoded{'pps'} : $pps),
                    "rateIncrease" => 100,
                    "autoBlacklisting" => "enabled",
                    "badActor" => "enabled",
                    "blacklistCategory" => $blacklist_category,
                    "blacklistDetectionSeconds" => 60,
                    "blacklistDuration" => 14400,
                    "perSourceIpDetectionPps" => round(($$decoded{'pps'} ? $$decoded{'pps'} : $pps) * 0.1),
                    "perSourceIpLimitPps"=> round(($$decoded{'pps'} ? $$decoded{'pps'} : $pps) * 0.1));
      push (@attack_vectors, \%method);
    }
     
    foreach my $service (@icmp_methods) {
      my %method = ("name" => $service,
                    "rateThreshold" => round(($$decoded{'pps_icmp'} ? $$decoded{'pps_icmp'} : $pps) * 2),
                    "rateLimit" => round($$decoded{'pps_icmp'} ? $$decoded{'pps_icmp'} : $pps),
                    "rateIncrease" => 100,
                    "autoBlacklisting" => "enabled",
                    "badActor" => "enabled",
                    "blacklistCategory" => $blacklist_category,
                    "blacklistDetectionSeconds" => 60,
                    "blacklistDuration" => 14400,
                    "perSourceIpDetectionPps" => round(($$decoded{'pps_icmp'} ? $$decoded{'pps_icmp'} : $pps) * 0.1),
                    "perSourceIpLimitPps"=> round(($$decoded{'pps_icmp'} ? $$decoded{'pps_icmp'} : $pps) * 0.1));
      push (@attack_vectors, \%method);
    }  
     
    foreach my $service (@tcp_methods) {
      my %method = ("name" => $service,
                    "rateThreshold" => round(($$decoded{'pps_tcp'} ? $$decoded{'pps_tcp'} : $pps) * 2),
                    "rateLimit" => round($$decoded{'pps_tcp'} ? $$decoded{'pps_tcp'} : $pps),
                    "rateIncrease" => 100,
                    "autoBlacklisting" => "enabled",
                    "badActor" => "enabled",
                    "blacklistCategory" => $blacklist_category,
                    "blacklistDetectionSeconds" => 60,
                    "blacklistDuration" => 14400,
                    "perSourceIpDetectionPps" => round(($$decoded{'pps_tcp'} ? $$decoded{'pps_tcp'} : $pps) * 0.1),
                    "perSourceIpLimitPps"=> round(($$decoded{'pps_tcp'} ? $$decoded{'pps_tcp'} : $pps) * 0.1));
      push (@attack_vectors, \%method);
    }
     
    foreach my $service (@udp_methods) {
      my %method = ("name" => $service,
                    "rateThreshold" => round(($$decoded{'pps_udp'} ? $$decoded{'pps_udp'} : $pps) * 2),
                    "rateLimit" => round($$decoded{'pps_udp'} ? $$decoded{'pps_udp'} : $pps),
                    "rateIncrease" => 100,
                    "autoBlacklisting" => "enabled",
                    "badActor" => "enabled",
                    "blacklistCategory" => $blacklist_category,
                    "blacklistDetectionSeconds" => 60,
                    "blacklistDuration" => 14400,
                    "perSourceIpDetectionPps" => round(($$decoded{'pps_udp'} ? $$decoded{'pps_udp'} : $pps) * 0.1),
                    "perSourceIpLimitPps"=> round(($$decoded{'pps_udp'} ? $$decoded{'pps_udp'} : $pps) * 0.1));
      push (@attack_vectors, \%method);
    }
    my @packet_types = ("suspicious", "icmp", "udp-flood", "dns-query-a", "dns-query-ptr", "dns-query-ns", "dns-query-soa", "dns-query-cname",
                        "dns-query-mx", "dns-query-aaaa", "dns-query-txt", "tcp-psh-flood", "dns-query-srv", "dns-query-axfr", "dns-query-ixfr",
                        "dns-query-any", "dns-query-other", "sip-method-invite", "sip-method-ack", "sip-method-options", "sip-method-bye",
                        "sip-method-cancel", "ipfrag", "sip-method-register", "sip-method-publish", "sip-method-notify", "sip-method-subscribe",
                        "sip-method-message", "sip-method-prack", "sip-method-other", "sip-method-malformed", "sip-uri-limit", "ipv4-any-other",
                        "exthdr", "ipv4-all", "ipv6-any-other", "ipv6-all", "tcp-syn-only", "tcp-synack", "tcp-rst", "host-unrch", "tidcmp");
    my %sweep = ("name" => "sweep",
                 "packetTypes" => \@packet_types,
                 "rateThreshold" => round(($$decoded{'pps'} ? $$decoded{'pps'} : $pps) * 2),
                 "rateLimit" => round($$decoded{'pps'} ? $$decoded{'pps'} : $pps),
                 "rateIncrease" => 100,
                 "autoBlacklisting" => "enabled",
                 "blacklistCategory" => $blacklist_category,
                 "blacklistDetectionSeconds" => 60,
                 "blacklistDuration" => 14400);
    push (@attack_vectors, \%sweep);
    my %net_vectors = ("networkAttackVector" => \@attack_vectors);
    my %dos_network = ($vs_name => \%net_vectors);
    %dos_profile = ("name" => $vs_name,
                    "description" => "Flowmon DDoS dos profile for Attack ID ".$attack_id,
                    "dosNetwork" => \%dos_network);
                                                         
    # send profile to appliance to create it                                     
    $client->POST('/mgmt/tm/security/dos/profile', encode_json(\%dos_profile));
    
    if ($client->responseCode() eq '200') {
      print {$fh} localtime() . " INFO: Profile " .$vs_name. " successfully created.\n"; 
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Profile " .$vs_name. " was not created. Error: ".$$json_hash_ref{'message'}."\n";
    }  
  }  
} # end createDP($vs_name, $attack_id)

#-------------------------------------------------------------------------------
# Function to delete DOS profile
# string $vs_name name of profile to delete
sub deleteDP {
  my ($vs_name) = @_;
  
  $client->DELETE('/mgmt/tm/security/dos/profile/dos_'.$vs_name);
  
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: DOS profile " .$vs_name. " successfully deleted.\n";  
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Profile " .$vs_name. " was not deleted. Error: ".$$json_hash_ref{'message'}."\n";
  } 
} # end deleteDP($vs_name)