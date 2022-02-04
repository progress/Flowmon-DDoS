#!/usr/bin/perl
# Script to provide configuration to Fortinet FortiDDoS appliance E version (tested on v5.6.0)
# Author:  Jiri Knapek <jiri.knapek@progress.com>
# Version: 1.0

package FortiDDoSClient;
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

require '/data/components/fortiddos/etc/FortiDDoSConfig.pl';

my $username = get_user();
my $password = get_password();
my $ip = get_ip();
my $debug = get_debug();
my $client = undef;

# database configuration
# install "libdbd-sqlite3-perl" package to support SQLite DB
my $driver = "SQLite";
my $database = "/data/components/fortiddos/etc/attacks.db";
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $pass = "";
#

# Here we take the only argument of script which is file name where is stored
# the detail of attack in JSON format
my ($iad_parametres_file) = $ARGV[0];
my ($template) = $ARGV[1] || "Flowmon_zone_template";

# Load the details into the string
open (FILE, $iad_parametres_file) or die "Couldn't open file: $!";
binmode FILE;
my $iad_params = <FILE>;
close FILE;
open (my $fh, ">>", "/data/components/fortiddos/log/iad.log");

# Open connection into attackDB
my $dbh = connectDB();

if (not defined $iad_parametres_file) {
  print {$fh} localtime() . " FATAL: Parameter with attack not passed from the script!\n";
  die "Fatal: Parameter not passed from the script, exiting";
}

my $decoded = decode_json($iad_params);
my $attsub = join(', ' , @{$$decoded{'subnets_atk'}});
my $attstart = scalar(localtime($$decoded{'attackstart'}));

if ( $template eq "install" ) {
  install();
} else {
  # Login into the appliance and set up needed token
  my $return = clientLogin();

  # Attack started we will need to configure a device
  if ($$decoded{'event'} eq 'statistics') {
    if ($return ne 'fail') {
      print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " detected, attack signature: ".$$decoded{'attacksignature'}."\n";
      # check which SPP is free
      my $spp = getFreeSPP();
      # create network object at the SPP
      if ($spp) {
        createGlobalPolicy($spp);
      }
      # Mark SPP as used
      setSPP($spp);

      # SEt proper thresholds
      setThresholds($spp);

      print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
    }
    else {
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Connection to FortiDDoS was not established.\n";
      }
    }
  }
  # Attack signature is updated so let's update the SPP list also
  elsif ($$decoded{'event'} eq 'signature_update') {
    if ($return ne 'fail') {
      # check which SPP is used for attack ID
      my $spp = getSPP();
      # update network objects at SPP
      # create network object at the SPP
      if ($spp) {
        createGlobalPolicy($spp);
      } else {
        print {$fh} localtime() . " ERROR: Couldn't identify SPP\n";
        return;
      }
      print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
    }
    else {
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Connection to FortiDDoS was not established.\n";
      }
    }
  }

  # Attack is over so it's time to remove the config from device
  elsif ($$decoded{'event'} eq 'ended') {
    if ($return ne 'fail') {
      print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
      print {$fh} localtime() . " INFO: Deleting segments from appliance\n";
      my $segments = getSegments();
      foreach my $row (@$segments) {
        my ($id) = @$row;
        my $mkey = $$decoded{'segment'}."-".$id;
        # Delete network obejects
        deleteGlobalPolicy($mkey);
      }
      # Mark in DB the SPP as free to use
      freeSPP();
      # delete from DB IDs of the segments used for this attack
      deleteSegments();
    } else {
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Connection to FortiDDoS was not established.\n";
      }
    }
  } else {
    print {$fh} localtime() . " INFO: Unconfigured action detected, exiting.\n";
  }
}
# Disconnect from attackDB
disconnectDB();

###################################################################################
# General Function

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

################################################################################
# API functions

#-------------------------------------------------------------------------------
# Function to login into the FortiDDoS in order to be able to start commanding it
# no parameters are required here
sub clientLogin {

    my $retval;

    my $ua = LWP::UserAgent->new( cookie_jar => {} );
    $client = REST::Client->new( { useragent => $ua } );
    $client->getUseragent()->ssl_opts( 'verify_hostname' => 0 );
    $client->setHost('https://'.$ip);
    $client->addHeader('Content-Type', 'application/json');
    $client->addHeader('Accept', 'application/json');

    $client->POST('/api/authenticate/', '{"username": "'.$username.'", "password": "'.$password.'"}');

    if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " INFO: Connected to FortiDDoS " .$ip. " successfully.\n";
        my $json_hash_ref = decode_json($client->responseContent());
        
        $client->addHeader('Authorization', 'Bearer '.$$json_hash_ref{'access_token'});
        $retval = $client->responseCode();
    } else {
        $retval = $client->responseCode();

        if ($client->responseCode() eq '403') {
            print {$fh} localtime() . " ERROR: Authentication to FortiDDoS " .$ip. " failed.\n";
            if ($debug) {
              print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
            }
            $retval = "fail";
        }
        ### unable to connect
        elsif ($client->responseCode() eq '500') {
            print {$fh} localtime() . " ERROR: Connection to FortiDDoS " .$ip. " failed. No such host.\n";
            if ($debug) {
              print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
            }
            $retval = "fail";
        } else {
            print {$fh} localtime() . " ERROR: Connection to FortiDDoS " .$ip. " failed. General error.\n";
            if ($debug) {
              print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
            }
            $retval = "fail";
        }
    }

    return $retval;
} # end clientLogin()

#-------------------------------------------------------------------------------
# Function to create a global protection profile for a certain customer and IP address
# string $spp Name of the SPP we are going to use for this mitigation
sub createGlobalPolicy {

  my $retval;
  my ($spp) = @_;

  my $data;
  $$data{'spp'} = $spp;
  $$data{'alt-spp-enable'} = "disable";
  $$data{'alt-spp'} = "";
  $$data{'threshold-mbps'} = "3072";
  $$data{'threshold'} = "4464285";
  $$data{'threshold-per-million'} = "1000000";
  $$data{'comment'} = "ID ".$$decoded{'attackId'}." Segment: ".$$decoded{'segment'};


  # We will go through configured subnets and create ip list for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    # Parse the IP to get IP and MASK
    my $ip_seg = new Net::IP (ipAddressNormalize($subnet)) or die (Net::IP::Error());
    my $subid = storeSegment($subnet);
    $$data{'mkey'} = $$decoded{'segment'}."-".$subid;
    $$data{'subnet-id'} = $subid;

    # let's check if it's IP v4 or v6
    if ($ip_seg->version() == 4)
    {
      $$data{'ip-version'} = "IPv4";
      $$data{'ip-addr-mask'} = $subnet;
      $$data{'ipv6-addr-prefix'} = "::/0";
    }
    else {
      $$data{'ip-version'} = "IPv6";
      $$data{'ip-addr-mask'} = "0.0.0.0/0";
      $$data{'ipv6-addr-prefix'} = $subnet;
    }
    my %seg = ( "data" => $data);
    # Send the SPP policy to the FortiDDoS
    $client->POST('/api/v2/ddos/global/ddos-global-spp-policy/', encode_json(\%seg));

    if ($client->responseCode() eq '201') {
      print {$fh} localtime() . " INFO: New Global SPP Policy for subnet " .$subnet. " created successfully.\n";
      $retval = $client->responseCode();
    } else {
      $retval = $client->responseCode();
      print {$fh} localtime() . " ERROR: New Global SPP policy for subnet " .$subnet. " failed. General error.\n";
      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }
  
  return $retval;
} # end createGlobalPolicy

#-------------------------------------------------------------------------------
# Function to configure the correct Scalar thresholds for the attack
# string $spp Name of the SPP we are going to use for this mitigation
sub setThresholds {

  my $retval;
  my ($spp) = @_;

  my $data;
  # -------------------- SCALARS HERE ------------------------------------------
  # Create SYN threshold
  $$data{'mkey'} = "SYN";
  $$data{'type'} = "syn";
  $$data{'inbound-threshold'} = ($$decoded{'pps_tcp_s'} eq 0 ? "1000" : '"'.round($$decoded{'pps_tcp_s'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  my %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: SYN threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: SYN threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: SYN threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create SYN per source threshold
  $$data{'mkey'} = "SYNPS";
  $$data{'type'} = "syn-per-src";
  $$data{'inbound-threshold'} = ($$decoded{'pps_tcp_s'} eq 0 ? "100" : '"'.round($$decoded{'pps_tcp_s'} * 0.1).'"');
  $$data{'outbound-threshold'} = "16777215";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: SYN per source threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: SYN per source threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: SYN per source threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create Most active source threshold
  $$data{'mkey'} = "MAS";
  $$data{'type'} = "most-active-source";
  $$data{'inbound-threshold'} = ($$decoded{'pps'} eq 0 ? "100" : '"'.round($$decoded{'pps'} * 0.2).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: Most active source threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: Most active source threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: Most active source threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create New connections source threshold
  $$data{'mkey'} = "NC";
  $$data{'type'} = "new-connections";
  $$data{'inbound-threshold'} = ($$decoded{'pps_tcp_s'} eq 0 ? "100" : '"'.round($$decoded{'pps_tcp_s'} * 0.1).'"');
  $$data{'outbound-threshold'} = "16777215";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: New connections threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: New connections threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: New connections threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create DNS Query threshold
  $$data{'mkey'} = "DNSQ";
  $$data{'type'} = "dns-query";
  $$data{'inbound-threshold'} = ($$decoded{'pps_dns'} eq 0 ? "1000" : '"'.round($$decoded{'pps_dns'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: DNS Query threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: DNS Query threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: DNS Query threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create DNS response threshold
  $$data{'mkey'} = "DNSR0";
  $$data{'type'} = "dns-rcode-no-error";
  $$data{'inbound-threshold'} = ($$decoded{'pps_dns'} eq 0 ? "2000" : '"'.round($$decoded{'pps_dns'} * 0.7).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: DNS response threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: DNS response threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: DNS response threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create DNS response with error threshold
  $$data{'mkey'} = "DNSR15";
  $$data{'type'} = "dns-rcode-error";
  $$data{'inbound-threshold'} = ($$decoded{'pps_dns'} eq 0 ? "2000" : '"'.round($$decoded{'pps_dns'} * 0.1).'"');
  $$data{'outbound-threshold'} = "65535";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: DNS response with error threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_scalar/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: DNS response with error threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: DNS response with error threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }
  # -------------------- SCALARS ENDS ------------------------------------------
  # ------------------- Protocols HERE -----------------------------------------
  # Create TCP threshold
  $$data{'mkey'} = "TCP";
  $$data{'protocol-start'} = "6";
  $$data{'protocol-end'} = "6";
  $$data{'inbound-threshold'} = ($$decoded{'pps_tcp'} eq 0 ? "1000" : '"'.round($$decoded{'pps_tcp'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: TCP threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: TCP threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: TCP threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create UDP threshold
  $$data{'mkey'} = "UDP";
  $$data{'protocol-start'} = "17";
  $$data{'protocol-end'} = "17";
  $$data{'inbound-threshold'} = ($$decoded{'pps_udp'} eq 0 ? "1000" : '"'.round($$decoded{'pps_udp'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: UDP threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: UDP threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: UDP threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create ICMP threshold
  $$data{'mkey'} = "ICMP";
  $$data{'protocol-start'} = "1";
  $$data{'protocol-end'} = "1";
  $$data{'inbound-threshold'} = ($$decoded{'pps_icmp'} eq 0 ? "1000" : '"'.round($$decoded{'pps_icmp'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: ICMP threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: ICMP threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: ICMP threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create ALL0 threshold
  $$data{'mkey'} = "ALL0";
  $$data{'protocol-start'} = "0";
  $$data{'protocol-end'} = "0";
  $$data{'inbound-threshold'} = ($$decoded{'pps'} eq 0 ? "1000" : '"'.round($$decoded{'pps'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: ALL0 threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: ALL0 threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: ALL0 threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create ALL1 threshold
  $$data{'mkey'} = "ALL1";
  $$data{'protocol-start'} = "2";
  $$data{'protocol-end'} = "5";
  $$data{'inbound-threshold'} = ($$decoded{'pps'} eq 0 ? "1000" : '"'.round($$decoded{'pps'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: ALL1 threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: ALL1 threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: ALL1 threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create ALL3 threshold
  $$data{'mkey'} = "ALL3";
  $$data{'protocol-start'} = "18";
  $$data{'protocol-end'} = "255";
  $$data{'inbound-threshold'} = ($$decoded{'pps'} eq 0 ? "1000" : '"'.round($$decoded{'pps'}).'"');
  $$data{'outbound-threshold'} = "134217727";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: ALL3 threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_protocol/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: ALL3 threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: ALL3 threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }
  # ------------------- Protocols ENDS -----------------------------------------
  # ------------------- TCP ports HERE -----------------------------------------
  # Create HTTP threshold
  $$data{'mkey'} = "HTTP";
  $$data{'port-start'} = "80";
  $$data{'port-end'} = "80";
  $$data{'inbound-threshold'} = ($$decoded{'pps_http'} eq 0 ? "1000" : '"'.round($$decoded{'pps_http'}).'"');
  $$data{'outbound-threshold'} = "16777215";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_tcp_ports/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: HTTP threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_tcp_ports/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: HTTP threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: HTTP threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }

  # Create HTTPS threshold
  $$data{'mkey'} = "HTTPS";
  $$data{'port-start'} = "443";
  $$data{'port-end'} = "443";
  $$data{'inbound-threshold'} = ($$decoded{'pps_https'} eq 0 ? "1000" : '"'.round($$decoded{'pps_https'}).'"');
  $$data{'outbound-threshold'} = "16777215";
  %seg = ( "data" => $data);
  # Send the Threshold scalars to the FortiDDoS
  $client->POST('/api/v2/spp/'.$spp.'/ddos_spp_threshold_tcp_ports/', encode_json(\%seg));

  if ($client->responseCode() eq '201') {
    print {$fh} localtime() . " INFO: HTTPS threshold set to " .$$data{'inbound-threshold'}. ".\n";
    $retval = $client->responseCode();
  } else {
    # It has failed so it might already exist, lets try to update the existing one
    $client->PUT('/api/v2/spp/'.$spp.'/ddos_spp_threshold_tcp_ports/', encode_json(\%seg));
    if ($client->responseCode() eq '204') {
      print {$fh} localtime() . " INFO: HTTPS threshold set to " .$$data{'inbound-threshold'}. ".\n";
      $retval = $client->responseCode();
    } else {
      print {$fh} localtime() . " ERROR: HTTPS threshold was not set to " .$$data{'inbound-threshold'}. ". General error.\n";

      if ($debug) {
        print {$fh} localtime() . " DEBUG: Code ".$client->responseCode()." :" .$client->responseContent()."\n";
      }
      $retval = "fail";
    }
  }
  # ------------------- TCP ports ENDS -----------------------------------------
  return $retval;
} # end setThresholds

#-------------------------------------------------------------------------------
# Function to delete all the policies and free it for next attack
# string $mkey Key name to work with
sub deleteGlobalPolicy {

  my $retval;
  my ($mkey) = @_;
  $client->DELETE('/api/v2/ddos/global/ddos-global-spp-policy/'.$mkey.'/');

  if ($client->responseCode() > '204') {
    $retval = "host";
    my $json_hash_ref = decode_json($client->responseContent());
    print {$fh} localtime() . " INFO: Cannot delete segment $mkey! Error code: ".$$json_hash_ref{'error_code'}."\n";

    if ($debug) {
      print {$fh} localtime() . " DEBUG: " .$client->responseContent()."\n";
    }
  }
  elsif ($client->responseCode() eq '204') {
    print {$fh} localtime() . " INFO: Segment $mkey deleted successfully.\n";
    $retval = $client->responseCode();
  }
} # end deleteGlobalPolicies

# ------------------------------------------------------------------------------
# Function to install all required configuration into the A10 FortiDDoS box
# no parameters here
sub install {
  print {$fh} localtime() . " INFO: Starting installation procedure to prepare FortiDDoS for integration with Flowmon.\n";
  ###############################################################################
  # Create GLID
  print {$fh} localtime() . " INFO: Creating Structures in dabatabse.\n";
  # create DDD SPPs in DB to be used
  my $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-1", 0));
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
  $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-2", 0));
  $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
  $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-3", 0));
  $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
  $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-4", 0));
  $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
  $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-5", 0));
  $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
  $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-6", 0));
  $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
  $stmt = qq(INSERT INTO spp (name,attackid) VALUES ("DDD-7", 0));
  $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";
} # end install()

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
  
  # Create table for the SPPs
  my $query = qq(CREATE TABLE spp (name TEXT,attackid INT););
  my $rv = $dbopen->do($query);

  if($rv < 0){
    print $DBI::errstr;
  } else {
    # Create table for the SPPs
    my $query = qq(CREATE TABLE segments (id INT,segment TEXT,attackid INT););
    my $rv = $dbopen->do($query);
      if($rv < 0){
        print $DBI::errstr;
      } else {
        if ($debug) {
          print {$fh} localtime() . " DEBUG: AttackDB - Table structure for attacks was created successfully.\n";
        }
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

# To receive one of the free SPPs from database to use for the attack
sub getFreeSPP {
  my $spp = 0;
  $spp = $dbh->selectrow_array("SELECT name FROM spp WHERE attackid = 0 LIMIT 1");
  if ($spp gt 0) {
    if ($debug) {
      print {$fh} localtime() . " DEBUG: Selected SPP: " . $spp . "\n";
    }
    return $spp;
  } else {
    print {$fh} localtime() . " ERROR: There is no free SPP to use for this attack.\n";
    return 0;
  }
}

# Get the right SPP for update of attack
sub getSPP {
  my $spp = $dbh->selectrow_array("SELECT name FROM spp WHERE attackid = $$decoded{'attackId'}");
  if ($spp gt 0){
    if ($debug) {
      print {$fh} localtime() . " DEBUG: Found SPP " . $spp . " for the attack $$decoded{'attackId'}\n";
    }
    return $spp;
  } else {
    print {$fh} localtime() . " ERROR: There is no SPP for this attack.\n";
    return 0;
  }
}

# Here we pair attack ID with SPP
sub setSPP {
  
  my ($spp) = @_;
  my $stmt = qq(UPDATE spp SET attackid = $$decoded{'attackId'} WHERE name = "$spp");
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";

  if ($debug) {
    print {$fh} localtime() . " DEBUG: FortiDDoS SPP information for $$decoded{'attackId'} has been stored into database successfully.\n";
  }
  return;
}

# Mark in DB the SPP as free
sub freeSPP {
  my $stmt = qq(UPDATE spp SET attackid = 0 WHERE attackid = $$decoded{'attackId'});
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";

  if ($debug) {
    print {$fh} localtime() . " DEBUG: FortiDDoS SPP information for $$decoded{'attackId'} has been marked as free.\n";
  }
  return;
}

# To receive one of the free SPPs from database to use for the attack
sub storeSegment {
  my ($subnet) = @_;
  # First we need to find the highets ID in DB
   my $max_id = 0;
  $max_id = $dbh->selectrow_array("SELECT MAX(id) FROM segments");
  if ($max_id gt 0){
    if ($debug) {
      print {$fh} localtime() . " DEBUG: Found segment ID: " . $max_id . "\n";
    }
  } else {
    if ($debug) {
      print {$fh} localtime() . " DEBUG: There are currently no segments under mitigation.\n";
    }
  }

  $max_id++;

  my $stmt = qq(INSERT INTO segments (id,segment,attackid) VALUES ($max_id, "$subnet", $$decoded{'attackId'}));
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";

  if ($debug) {
    print {$fh} localtime() . " DEBUG: FortiDDoS information for $subnet has been stored into database successfully.\n";
  }
  return $max_id;
}

# Get all segments for the attack
sub getSegments {
  my $segments = $dbh->selectall_arrayref("SELECT id FROM segments WHERE attackid = $$decoded{'attackId'}");
  if ($segments gt 0){
    if ($debug) {
      print {$fh} localtime() . " DEBUG: Found segments for the attack $$decoded{'attackId'}\n";
    }
    return $segments;
  } else {
    print {$fh} localtime() . " ERROR: There is no segment for this attack.\n";
    return 0;
  }
}

# Delete segments from DB
sub deleteSegments {
  my $stmt = qq(DELETE FROM segments WHERE attackid = $$decoded{'attackId'});
  my $rv = $dbh->do($stmt) or print {$fh} localtime() . " ERROR: Unable to write to database. " . $DBI::errstr . "\n";

  if ($debug) {
    print {$fh} localtime() . " DEBUG: FortiDDoS segments for attack $$decoded{'attackId'} have been deleted from database.\n";
  }
  return;
}

