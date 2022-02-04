#!/usr/bin/perl
# Script to provide configuration to Open vSwitch v2.5.1 via Floodlight controller
# version 1.0
# released 2017/08/16
# Flowmon Networks (c) 2017

package ovsFloodlight;
use strict;
use Exporter;
use Data::Dump qw(dump);
use REST::Client;
use JSON;
use HTTP::Request::Common; 
use Net::IP;
use POSIX qw(strftime);

### check whether lock exists

my $counter = 0;
my $test = open(TEMP, "<:encoding(UTF-8)", "/tmp/DDoS_LOCK");

while ($test != undef) {
  
  sleep(5);

  $test = open(TEMP, "<:encoding(UTF-8)", "/tmp/DDoS_LOCK");

  $counter++;
 
  if ($counter > 4) {
    die "Lock detected! Exiting.."."\n";
  } 
}

close TEMP;


#log to floodlight
my $ip = '192.168.60.2:8080'; # here insert IP where your Floodlight controller is running
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
print {$fh} localtime() . "$iad_params\n";

my $decoded = decode_json($iad_params);

### get DDoS attack ID into a global variable and save name of the file that is to be created further
my $attack_ID = $$decoded{'attackId'};
my $filename = "/tmp/DDoS_attack_ID_".$attack_ID;


 print {$fh} localtime() . "Before computing statistics..\n";

if ($$decoded{'event'} eq 'statistics') {

 print {$fh} localtime() . "Passed into computing statistics..\n";

### create a uniqe new file for this DDoS ID 

  open(TEMP, ">", $filename);
  close TEMP;
}

 print {$fh} localtime() . "After computing statistics..\n";


# Login into the appliance and set up needed token
my $return = clientLogin();


### create lock
open(TEMP, ">", "/tmp/DDoS_LOCK");
close TEMP;

my $lock = "/tmp/DDoS_LOCK";


# Attack started we will need to configure a device
if ($$decoded{'event'} eq 'statistics') {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " detected, attack signature: ".$$decoded{'attacksignature'}."\n";

  # We will go through configured subnets and create profiles for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
    
    # first we create DOS profile
    print {$fh} localtime() . " INFO: Creating zone profile for subnet ".$subnet."\n";
    createACL($subnet); #subnet under attack
  }

  print {$fh} localtime() . " INFO: Appliance configuration was finished.\n";
}




# Attack is over so it's time to remove the config from device
elsif ($$decoded{'event'} eq 'ended') {
  print {$fh} localtime() . " INFO: Attack ".$$decoded{'attackId'}. " ended, attack signature: ".$$decoded{'attacksignature'}."\n";
  print {$fh} localtime() . " INFO: Deleting profiles from appliance\n";
  
  # We will go through configured subnets and delete profiles for all of them
  foreach my $subnet (@{$$decoded{'subnets_atk'}}) {
     deleteACL($subnet);
  }
} else {
  print {$fh} localtime() . " INFO: Unconfigured action detectected, exiting.\n";  
}

### delete lock 
unlink $lock;
$lock = undef;



################################################################################
# API functions

#-------------------------------------------------------------------------------
# Function to login into the Floodlight Controller in order to be able to start commanding it
# no parametres are required here
sub clientLogin {

    my $retval;

    $client = REST::Client->new();
    $client->setHost('http://'.$ip);
    $client->addHeader('Content-Type', 'application/json');
#test whether the appliance is accessible
    $client->GET('/wm/acl/rules/json');

    if ($client->responseCode() eq '200') {
        print {$fh} localtime() . " Connected to " .$ip. " successfully.\n";
        

        return 0;
    } else {
        $retval = $client->responseCode();
        
        
        if ($client->responseCode() eq '500') {            
            print {$fh} localtime() . " Connection to " .$ip. " failed. No such host.\n";
            $retval = "host";
        } else {
            print {$fh} localtime() . " Connection to " .$ip. " failed. General error.\n";
            $retval = "generic";
        }
    }

    return $retval;
} # end clientLogin()

#-------------------------------------------------------------------------------
# Function to create an ACL rule to protect a segment
# string $subnet protected network segment
sub createACL { 

  my $retval;
  my ($subnet) = @_;
  
  my %acl_config;

  # parse through the attack signature to find ports and protocol used for attack
  my $signature_rule_count = 0;
  my $inspected_rules = 0;

    # get number of subrules in the whole attack signature 
    while ( $$decoded{'attacksignature'} =~ /\((.+?)\)/g) {
	$signature_rule_count++;
    }

    # find icmp DDoS in the signature
    while ($$decoded{'attacksignature'} =~ /icmp/g) {
      %acl_config = ("nw-proto" => '1',"dst-ip" => $subnet ,"action" => "deny");
      print {$fh} localtime() . " Protocol of the attack is icmp..\n";
      
      # send the ACL config to SDN controller
      $client->POST('/wm/acl/rules/json', encode_json(\%acl_config));
	
      # get an ID of the created rule
      $client->GET('/wm/acl/rules/json');

      my $decoded_json = decode_json($client->responseContent());

      my $json_hash_ref = decode_json($client->responseContent());

      # check connection
      if ($client->responseCode() > '200') {
        $retval = "host";
        dump($json_hash_ref);
        print {$fh} localtime() . " Cannot create a ACL entry! Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
      } elsif ($client->responseCode() eq '200') {
          print {$fh} localtime() . " ACL entry $subnet created successfully.\n";
          $retval = $client->responseCode();
      }


      my $temp = pop(@$decoded_json);
      my $ACL_rule_ID = $$temp{'id'};
      print {$fh} localtime() . "ACL rule ID saved to the file '$filename' is $ACL_rule_ID\n";

      ### append the ACL rule ID to the relevant DDoS attack file
      open(TEMP, ">>", $filename) or die "Couldn't open the file in order to save ACL rule ID!";
      print TEMP $ACL_rule_ID;
      print TEMP '\n';
      close TEMP;

      $inspected_rules++;
    } 

    # find udp DDoS in the signature
    while ($$decoded{'attacksignature'} =~ /udp/g) {

      %acl_config = ("nw-proto" => 'UDP',"dst-ip" => $subnet ,"action" => "deny");
      print {$fh} localtime() . " Protocol of the attack is udp..\n";

           # send the ACL config to SDN controller
     $client->POST('/wm/acl/rules/json', encode_json(\%acl_config));

     # get an ID of the created rule
     $client->GET('/wm/acl/rules/json');

     my $decoded_json = decode_json($client->responseContent());

     my $json_hash_ref = decode_json($client->responseContent());

     # check connection
     if ($client->responseCode() > '200') {
       $retval = "host";
       dump($json_hash_ref);
       print {$fh} localtime() . " Cannot create a ACL entry! Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
     } elsif ($client->responseCode() eq '200') {
         print {$fh} localtime() . " ACL entry $subnet created successfully.\n";
         $retval = $client->responseCode();
     }

     my $temp = pop(@$decoded_json);
     my $ACL_rule_ID = $$temp{'id'};
     print {$fh} localtime() . "ACL rule ID saved to the file '$filename' is $ACL_rule_ID\n";

     ### append the ACL rule ID to the relevant DDoS attack file
     open(TEMP, ">>", $filename) or die "Couldn't open the file in order to save ACL rule ID!";
     print TEMP $ACL_rule_ID . "\n";
     close TEMP;

      $inspected_rules++;
    }


    # find tcp DDoS in the signature
    while ($$decoded{'attacksignature'} =~ /tcp/g) {
      %acl_config = ("nw-proto" => 'TCP',"dst-ip" => $subnet ,"action" => "deny");
      print {$fh} localtime() . " Protocol of the attack is tcp..\n";

      # send the ACL config to SDN controller
      $client->POST('/wm/acl/rules/json', encode_json(\%acl_config));

      # get an ID of the created rule
      $client->GET('/wm/acl/rules/json');

      my $decoded_json = decode_json($client->responseContent());

      my $json_hash_ref = decode_json($client->responseContent());

      # check connection
      if ($client->responseCode() > '200') {
        $retval = "host";
        dump($json_hash_ref);
        print {$fh} localtime() . " Cannot create a ACL entry! Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
      } elsif ($client->responseCode() eq '200') {
          print {$fh} localtime() . " ACL entry $subnet created successfully.\n";
          $retval = $client->responseCode();
      }

      my $temp = pop(@$decoded_json);
      my $ACL_rule_ID = $$temp{'id'};
      print {$fh} localtime() . " ACL rule ID saved to the file '$filename' is $ACL_rule_ID\n";

      ### append the ACL rule ID to the relevant DDoS attack file
      open(TEMP, ">>", $filename) or die " Couldn't open the file in order to save ACL rule ID!";
      print TEMP $ACL_rule_ID;
      print TEMP '\n';
      close TEMP;

      $inspected_rules++;
    }


    # find general DDoS in the signature
    if ($inspected_rules != $signature_rule_count) {
      %acl_config = ("dst-ip" => $subnet ,"action" => "deny");
      print {$fh} localtime() . " Protocol of the attack is not detected..\n";

           # send the ACL config to SDN controller
      $client->POST('/wm/acl/rules/json', encode_json(\%acl_config));

      # get an ID of the created rule
      $client->GET('/wm/acl/rules/json');

      my $decoded_json = decode_json($client->responseContent());

      my $json_hash_ref = decode_json($client->responseContent());

      # check connection
      if ($client->responseCode() > '200') {
        $retval = "host";
        dump($json_hash_ref);
        print {$fh} localtime() . " Cannot create a ACL entry! Error: ".$$json_hash_ref{'response'}{'err'}{'msg'}."\n";
      } elsif ($client->responseCode() eq '200') {
          print {$fh} localtime() . " ACL entry $subnet created successfully.\n";
          $retval = $client->responseCode();
      }

      my $temp = pop(@$decoded_json);
      my $ACL_rule_ID = $$temp{'id'};
      print {$fh} localtime() . "ACL rule ID saved to the file '$filename' is $ACL_rule_ID\n";

      ### append the ACL rule ID to the relevant DDoS attack file
      open(TEMP, ">>", $filename) or die " Couldn't open the file in order to save ACL rule ID!";
      print TEMP $ACL_rule_ID . "\n";
      close TEMP;
   }

  return $retval;                
} # end createACL

#-------------------------------------------------------------------------------
# Function to delete ACL rule from the configuration
sub deleteACL {

  print {$fh} localtime() . " Function to delete ACL triggered!\n";
  print {$fh} localtime() . " Filename is '$filename'\n";

  ### read the ACL rule ID from the relevant file and store it into a variable
  open(TEMP, "<:encoding(UTF-8)", $filename) or print {$fh} localtime () . "Couldn't open the file with ACL rule ID\n";
  
  while (my $rule_ID = <TEMP>) {

    print {$fh} localtime() . "ACL rule ID is $rule_ID\n";
    print {$fh} localtime() . "File opened..\n";

    $client->request('DELETE','/wm/acl/rules/json','{"ruleid" : '.$rule_ID.'}');

    print {$fh} localtime() . "Rule deleted?\n";
  }

  close TEMP;


# delete the relevant file
unlink $filename;
$filename = undef;

} # end deleteACL
