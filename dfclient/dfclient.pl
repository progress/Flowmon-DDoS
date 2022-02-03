#! /usr/bin/perl -w
# Script to inform Radware DefenseFlow about attack detect, update and stop by Flowmon DDoS Defender
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>, Vojtech Hodes <vojtech.hodes@flowmon.com>
# Version: 0.2

package dfClient;

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

# Username and password for the appliance
my $username = 'radware';
my $password = 'radware321';
my $ip = '192.168.47.72'; # Vision IP
my $client = undef;
my $ip_seg = undef;


# Here we take the only argument of script which is file name where is stored
# the detail of attack in JSON format
my ($iad_parametres_file) = $ARGV[0];

if (not defined $iad_parametres_file) {
  die "Fatal: Parameter not passed form the script, exiting";
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
  
  startAttack($$decoded{'attackId'});

  print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
}


# If there's a change in attack's characteristics, let's update the signature

elsif ($$decoded{'event'} eq 'signature_update')  {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " updated, new attack signature: ".$$decoded{'attacksignature'}."\n";

# ... and setup the updated/new one
  updateAttack($$decoded{'attackId'});
}


# Attack is over so it's time to remove the config from device
elsif ($$decoded{'event'} eq 'ended') {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
  print {$fh} localtime() . " INFO: Informing DefenceFlow about end of attack.\n";
     
  stopAttack($$decoded{'attackId'});
}
else {  
  print {$fh} localtime() . " INFO: Unconfigured event type: ".$$decoded{'event'}." detected in file ".$iad_parametres_file."\n";  
  print {$fh} localtime() . " ERROR: DefenceFlow appliance could not be configured!\n";
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
# no parameters required here
sub clientLogin {

    my $retval;

    $client = REST::Client->new();
    $client->getUseragent()->ssl_opts( 'verify_hostname' => 0 );
    $client->setHost('https://'.$ip);
    $client->addHeader('Content-Type', 'application/json');

    $client->POST('/mgmt/system/user/login', '{"username":"'.$username.'","password":"'.$password.'"}');
    if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " INFO: Connected to DefenceFlow " .$ip. " successfully.\n";
        $retval = $client->responseCode();
        my $json_hash_ref = decode_json($client->responseContent());
        
        # Add authentication token to header to perform additional actions
        $client->addHeader('Cookie', 'JSESSIONID='.$$json_hash_ref{'jsessionid'});
        $client->addHeader('JSESSIONID', $$json_hash_ref{'jsessionid'});

        return 0;
    } else {
        $retval = $client->responseCode();

        if ($client->responseContent() =~ m/Invalid Username or invalid Password/) {
            print {$fh} localtime() . " ERROR: Authentication to DefenceFlow " .$ip. " failed.\n";
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
# Function to inform DefenceFlow about attack start
# requires following parameters
# int $attack_id attack ID from DDoS Defender
sub startAttack {
  my ($attack_id) = @_;
  
  my @network;
  
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    # parse IP to get IP and prefix
    my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());
    
    my %subnet = ("ip" => $ip_seg->ip(),
                  "prefix" => $ip_seg->prefixlen());
    
    push (@network, \%subnet);
  }
  
  my %networks = ("networks" => \@network);
  
  my %baseline = ("baselineIcmpBytesPerSecond" => $$decoded{'bandwidth_icmp'},
                  "baselineIcmpPacketsPerSecond" => $$decoded{'pps_icmp'},
                  "baselineTcpBytesPerSecond" => $$decoded{'bandwidth_tcp'},
                  "baselineTcpPacketsPerSecond" => $$decoded{'pps_tcp'},
                  "baselineUdpBytesPerSecond" => $$decoded{'bandwidth_udp'},
                  "baselineUdpPacketsPerSecond" => $$decoded{'pps_udp'});
  
  my %post = ("externalAttackId" => "FM_".$attack_id,
              "alertInfo" => "Flowmon DDoS Attack ID ".$attack_id,
              "networksDetails" => \%networks,
              "baselinesIpv4" => \%baseline,
              "baselinesIpv6" => \%baseline);
                      
  # send attack details to appliance                                     
  $client->POST('/mgmt/device/df/config/action/attackstart', encode_json(\%post));
  
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Device informed about attack FM_".$attack_id." successfully.\n";  
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Attack  " .$attack_id. " was not started. Error: ".$$json_hash_ref{'message'}."\n";
  }                   
} # end startAttack($attack_id)


#-------------------------------------------------------------------------------
## Function to inform DefenseFlow about attack UPDATE
## requires following parameters
## int $attack_id attack ID from DDoS Defender


sub updateAttack {
  my ($attack_id) = @_;
#  print $attack_id;

  my @network;

  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    # parse IP to get IP and prefix
    my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());

    my %subnet = ("ip" => $ip_seg->ip(),
                  "prefix" => $ip_seg->prefixlen());

    push (@network, \%subnet);
  }

  my %networks = ("networks" => \@network);

  my %baseline = ("baselineIcmpBytesPerSecond" => $$decoded{'bandwidth_icmp'},
                  "baselineIcmpPacketsPerSecond" => $$decoded{'pps_icmp'},
                  "baselineTcpBytesPerSecond" => $$decoded{'bandwidth_tcp'},
                  "baselineTcpPacketsPerSecond" => $$decoded{'pps_tcp'},
                  "baselineUdpBytesPerSecond" => $$decoded{'bandwidth_udp'},
                  "baselineUdpPacketsPerSecond" => $$decoded{'pps_udp'});

# Check whether file /tmp/DF-attack-$attack_id-updates.txt exists. If not, create it and set update attack ID to zero

  my $file = "/tmp/DF-attack-$attack_id-updates.txt";

  unless (-e $file) {

    my $attack_updateId=-1;
    open my $fh1, '>', "$file" or die "Couldn't open file $file";
    print $fh1 "$attack_updateId\n";
    close $fh1;
    print {$fh} localtime() . " INFO: $file created.\n";
}

# Read the only value from attack X updates file, increment the value
  open my $fh2, '<', "$file" or die "Couldn't open file $file";
  my $attack_updateId = <$fh2> + 1;
  $attack_updateId =~ s/\s*$//;
  close $fh2;

# and OVERWRITE it
  open my $fh3, '>', "$file" or die "Couldn't open file $file";;
  print $fh3 "$attack_updateId\n";
  close $fh3;
  print {$fh} localtime() . " INFO: ID of current attack update set to $attack_updateId.\n";


  my %post = ("externalAttackId" => "FM_".$attack_id."_".$attack_updateId,
              "alertInfo" => "Flowmon DDoS Attack ID FM_".$attack_id."_".$attack_updateId,
              "networksDetails" => \%networks,
              "baselinesIpv4" => \%baseline,
              "baselinesIpv6" => \%baseline);

  # send attack details to appliance
  $client->POST('/mgmt/device/df/config/action/attackstart', encode_json(\%post));

  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Device informed about attack update FM_".$attack_id."_".$attack_updateId." successfully"."\n";
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Attack update FM_".$attack_id."_".$attack_updateId." was not started. Error: ".$$json_hash_ref{'message'}."\n";
  }

  print {$fh} localtime() . " INFO: Updated appliance configuration was finished.\n";

} 

#-------------------------------------------------------------------------------
# Function to stop attack
# string $attack_id DDD attack ID
sub stopAttack {
  my ($attack_id) = @_;

# Check whether file /tmp/DF-attack-$attack_id-updates.txt exists. If so, read attack update ID

  my $file = "/tmp/DF-attack-$attack_id-updates.txt";
  my $attack_updateId = undef;  


  if (-e $file) {
 
    open my $fh2, '<', "$file" or die "Couldn't open file $file";
    my $attack_updateId = <$fh2>;
    $attack_updateId =~ s/\s*$//;
    close $fh2;

    # use attack ID as number of iterations
    while($attack_updateId != -1) {
      
      # delete attack update from DF
      my %post = ("externalAttackId" => "FM_".$attack_id."_".$attack_updateId);
     
      $client->POST('/mgmt/device/df/config/action/attackstop', encode_json(\%post));

      if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " INFO: Informed appliance that attack FM_".$attack_id."_".$attack_updateId." ended"."\n";
      } else {
         my $json_hash_ref = decode_json($client->responseContent());
         print {$fh} localtime() . " ERROR: Attack FM_".$attack_id."_".$attack_updateId." could not be stopped. Error: ".$$json_hash_ref{'message'}."\n";
      }
    
      $attack_updateId--;
    }
    # delete file with attack update ID
    unlink $file;   
  }
 
  # delete "parent" attack
  my %post = ("externalAttackId" => "FM_".$attack_id);
  
  $client->POST('/mgmt/device/df/config/action/attackstop', encode_json(\%post));
  
  if ($client->responseCode() eq '200') {
    print {$fh} localtime() . " INFO: Informed appliance that attack FM_" .$attack_id. " ended.\n";  
  } else {
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " ERROR: Attack " .$attack_id. " could not be stopped. Error: ".$$json_hash_ref{'message'}."\n";
  }
} # end stopAttack($attack_id)
