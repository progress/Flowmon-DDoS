#! /usr/bin/perl -w
# Script to configure F5 Silverline, tested to work with https://portal.f5silverline.com/docs/api/v1/index.md
# Author:  Jiri Knapek <jiri.knapek@flowmon.com>
# Version: 1.0

package f5Silverline;

use strict;
use REST::Client;
use JSON;
use HTTP::Request::Common;
use IO::Socket::SSL;
use Net::SSL;
use Net::IP;
use Net::IP qw(ip_get_version ip_expand_address ip_iptobin ip_bintoip);

# API token
my $token = '23423ks234234dfsdf234jhd02';
my $url = 'https://portal.f5silverline.com';
my $client = undef;

# Here we take the only argument of script which is filename where is stored
# the detail of attack in JSON format
my ($iad_parametres_file) = $ARGV[0];

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

# Initialize connection
my $return = clientInit();

# Attack started we will need to configure a device
if (($$decoded{'event'} eq 'statistics') or ($$decoded{'event'} eq 'signature_update')) {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " detected, attack signature: ".$$decoded{'attacksignature'}."\n";
  
  # We will go through subnets under attac and create routes for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
      createRoute($subnet);
  }
  print {$fh} localtime() . " INFO: F5 Silverline configuration was finished.\n";
}
# Attack is over so it's time to remove the config from F5 Silverline
elsif ($$decoded{'event'} eq 'ended') {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
  print {$fh} localtime() . " INFO: Deleting routes from Silverline\n";
  
  # We will go through configured subnets and delete profiles for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
      deleteRoute($subnet);
  }
  print {$fh} localtime() . " INFO: F5 Silverline configuration was finished.\n";
}
else {  
  print {$fh} localtime() . " INFO: Unconfigured event type: ".$$decoded{'event'}." detected in file ".$iad_parametres_file."\n";  
  print {$fh} localtime() . " ERROR: F5 Silverline could not be configured!\n";
}

################################################################################
# REST functions
#

#-------------------------------------------------------------------------------
# Initialize connection to the portal
# no parametres required here
sub clientInit {
    my $retval;
    $client = REST::Client->new();
    $client->setHost($url);
    $client->addHeader('Content-Type', 'application/json');
    $client->addHeader('X-Authorization-Token', $token);
}

#-------------------------------------------------------------------------------
# Here we use API to create a route
# string $subnet subnet to create
sub createRoute {
    my ($subnet) = @_;

    my %prefix = ("prefix" => $subnet);
    my %data = ("type" => "routes",
                "attributes" => \%prefix);
    my %route = ("data" => \%data);

    $client->POST('/api/v1/routes', encode_json(\%route));

    if ($client->responseCode() eq '201') {
      print {$fh} localtime() . " INFO: Route " .$subnet. " successfully created.\n"; 
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Route " .$subnet. " was not created. Error: ".$$json_hash_ref{'error'}."\n";
    }  
}

#-------------------------------------------------------------------------------
# Here we use API to create a route
# string $subnet subnet to create
sub deleteRoute {
    my ($subnet) = @_;

    my %prefix = ("prefix" => $subnet,
				  "comment" => "");
    my %data = ("type" => "routes",
                "attributes" => \%prefix);
    my %route = ("data" => \%data);

    $client->request('DELETE','/api/v1/routes', encode_json(\%route));
    
    if ($client->responseCode() eq '200') {
      print {$fh} localtime() . " INFO: Route " .$subnet. " successfully deleted.\n"; 
    } else {
      my $json_hash_ref = decode_json($client->responseContent());
      print {$fh} localtime() . " ERROR: Route " .$subnet. " was not deleted. Error: ".$$json_hash_ref{'error'}."\n";
    }  
}