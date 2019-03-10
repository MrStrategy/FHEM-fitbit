##############################################################################
# $Id: 32_fitbit.pm
#
#  32_fitbit.pm
#
#  2017 Tobias Vaupel
#  Based on code from 32_withings
#
#  https://forum.fhem.de/index.php/topic,73285
#
# ToDo:
#
##############################################################################
# Release 05 / 2019-03-10
# Fixed sleep values. Fitbit api was changed and sleep level were renamed.
# Module is now using the updated sleep levels. This causes the readings to have new names as well...
# Added support for heart rate. Module is reading summary of today as well as the values of previous day.
#
# Modification Strategy / 2019-03-09
# Added attribute createFriends - by default friends are no longer created
# Added attribute createDevices - by default devices are created but creation can be disabled.
# Added setWeight to insert a weigth value.
# Added setFat to insert a fat value
#Release 03 / 2017-09-03
# -match deviceID with "eq" instead of "==" to prevent warnings when device ID contains characters
# -battery readings content in lower case
# -added floors and elevation as USER reading
# Release 02 / 2017-07-01
# -commandref EN erstellt
# -reading summary_activeScore entfernt
# -fitbit_parseUserWeight: set reading weight
# -fhem() is used with silent param
# Release 01 / 2017-06-25
#  -fitbit_initDevice: reading von battery auf batteryLevel geändert.
# Release 00 / 2017-06-24
#  -Einige INTERNALs als Readings zur Verfügung gestellt
#  -FHEM sollte nicht mehr abstürzen, wenn der Token ungültig ist
#  -"weight" Daten werden zur Verfügung gestellt (API: Get Weight Logs)
#  -Sleep Daten der letzten Nacht werden ausgelesen (API: Get Sleep Logs by Date)
#  -Die eigentlich statischen Daten (Name,Geburtsdatum, Geschlecht etc.) je Device werden alle 6 Stunden neu ausgelesen
#  -Alle 6 Stunden wird nach neuen FRIEND, DEVICE, oder USER gesucht.
#  -Error Meldungen im JSON werden erkannt und ausgegeben.
#  -STATE per Reading state beschrieben.

package main;

use strict;
use warnings;
use HttpUtils;
use JSON;
use POSIX qw( strftime );
use Time::Local qw(timelocal);
use Digest::SHA qw(hmac_sha1_base64);
use Data::Dumper;
#ToDo: Per eval ausführen und Fehler abfangen + Fehlermeldung


sub fitbit_Initialize($) {
  my ($hash) = @_;
  Log3 "fitbit", 4, "fitbit: initialize";

  $hash->{DefFn}    = "fitbit_Define";
  $hash->{SetFn}    = "fitbit_Set";
  #$hash->{GetFn}    = "fitbit_Get";
  #$hash->{NOTIFYDEV} = "global";
  #$hash->{NotifyFn} = "fitbit_Notify";
  $hash->{UndefFn}  = "fitbit_Undefine";
  $hash->{AttrFn}   = "fitbit_Attr";
  $hash->{AttrList} = "IODev ".
                      "disable:0,1 ".
                      "interval ".
                      "createFriends:0,1 ".
                      "createDevices:0,1 ";
  $hash->{AttrList} .= $readingFnAttributes;
}

# Used by Subtype: ACCOUNT, DEVICE, USER, FRIEND
sub fitbit_Define($$) {
  my ($hash, $def) = @_;
  Log3 "fitbit", 3, "fitbit_Define() ".$def;

  my @a = split("[ \t][ \t]*", $def);

  my $subtype;
  my $name = $a[0];

  if( $a[2] eq "ACCOUNT" && @a == 4) {
    Log3 $name, 4, "$name: Define an account";
    my $tokenClear = $a[3];
    $subtype = "ACCOUNT";
    my $token = fitbit_encrypt($tokenClear);

    Log3 $name, 3, "$name: encrypt $tokenClear to $token" if($tokenClear ne $token);
    $hash->{DEF} = "ACCOUNT $token";
    $hash->{Clients} = ":fitbit:";
    $hash->{helper}{token} = $token;
  }
  else {
    return "Usage: define <name> fitbit ACCOUNT <OAuth 2.0 token>"  if(@a < 3 || @a > 4);
  }

  if( $a[2] eq "DEVICE" && @a == 4 ) {
    Log3 $name, 4, "$name: Define an DEVICE";
    $subtype = "DEVICE";
    my $deviceID = $a[3];

    $hash->{DEVICEID} = $deviceID;

    my $d = $modules{$hash->{TYPE}}{defptr}{"D$deviceID"};
    return "device $deviceID already defined as $d->{NAME}" if( defined($d) && $d->{NAME} ne $name );

    $modules{$hash->{TYPE}}{defptr}{"D$deviceID"} = $hash;

  }
  else {
    return "Usage: define <name> fitbit DEVICE <Device ID>"  if(@a < 3 || @a > 4);
  }

  if( $a[2] eq "USER" && @a == 4 ) {
    Log3 $name, 4, "$name: Define an USER";
    $subtype = "USER";
    my $userID = $a[3];

    $hash->{USERID} = $userID;
    readingsSingleUpdate($hash, "isFriend", "no", 1);

    my $d = $modules{$hash->{TYPE}}{defptr}{"U$userID"};
    return "device $userID already defined as $d->{NAME}" if( defined($d) && $d->{NAME} ne $name );

    $modules{$hash->{TYPE}}{defptr}{"U$userID"} = $hash;

  }
  else {
    return "Usage: define <name> fitbit USER <User ID>"  if(@a < 3 || @a > 4);
  }

  if( $a[2] eq "FRIEND" && @a == 4 ) {
    Log3 $name, 4, "$name: Define an FRIEND";
    $subtype = "FRIEND";

    my $userID = $a[3];

    $hash->{USERID} = $userID;
    readingsSingleUpdate($hash, "isFriend", "yes", 1);

    my $d = $modules{$hash->{TYPE}}{defptr}{"F$userID"};
    return "device $userID already defined as $d->{NAME}" if( defined($d) && $d->{NAME} ne $name );

    $modules{$hash->{TYPE}}{defptr}{"F$userID"} = $hash;

  }
  else {
    return "Usage: define <name> fitbit FRIEND <User ID>"  if(@a < 3 || @a > 4);
  }

  $hash->{NAME} = $name;
  $hash->{SUBTYPE} = $subtype;

  if(!defined( fitbit_isDNS() )) {
    Log3 $name, 3, "DNS Error";
    readingsSingleUpdate($hash, "state", "DNS Error", 1);
    InternalTimer( gettimeofday() + 900, "fitbit_InitWait", $hash, 0);
    return undef;
  }

  readingsSingleUpdate($hash, "state", "Initialized", 1);

  # is FHEM finished with initialize?
  if( $init_done ) {
    fitbit_initUser($hash, 0) if( $hash->{SUBTYPE} eq "USER" );
    fitbit_initFriend($hash, 0) if( $hash->{SUBTYPE} eq "FRIEND" );
    fitbit_connect($hash, 0) if( $hash->{SUBTYPE} eq "ACCOUNT" );
    fitbit_initDevice($hash) if( $hash->{SUBTYPE} eq "DEVICE" );
  }
  else {
    InternalTimer(gettimeofday()+15, "fitbit_InitWait", $hash, 0);
  }

  return undef;
}

sub fitbit_Get($$@) {
  # my ($hash, $name, $cmd) = @_;

  # my $list;
  # if( $hash->{SUBTYPE} eq "USER" ) {
    # $list = "update:noArg updateAll:noArg";

    # if( $cmd eq "updateAll" ) {
      # fitbit_poll($hash,2);
      # return undef;
    # }
    # elsif( $cmd eq "update" ) {
      # fitbit_poll($hash,1);
      # return undef;
    # }
  # } elsif( $hash->{SUBTYPE} eq "DEVICE" || $hash->{SUBTYPE} eq "DUMMY" ) {
    # $list = "update:noArg updateAll:noArg";
    # $list .= " videoLink:noArg" if(defined($hash->{modelID}) && $hash->{modelID} eq '21');
    # $list .= " videoCredentials:noArg" if(defined($hash->{modelID}) && $hash->{modelID} eq '22');
    # $list .= " settings:noArg" if(defined($hash->{modelID}) && $hash->{modelID} eq '60' && AttrVal($name,"IP",undef));


    # if( $cmd eq "videoCredentials" ) {
      # my $credentials = fitbit_getS3Credentials($hash);
      # return undef;
    # }
    # elsif( $cmd eq "videoLink" ) {
      # my $ret = "Flash Player Links:\n";
      # my $videolinkdata = fitbit_getVideoLink($hash);
      # if(defined($videolinkdata->{body}{device}))
      # {
        # #$hash->{videolink_ext} = "http://fpdownload.adobe.com/strobe/FlashMediaPlayback_101.swf?streamType=live&autoPlay=true&playButtonOverlay=false&src=rtmp://".$videolinkdata->{body}{device}{proxy_ip}.":".$videolinkdata->{body}{device}{proxy_port}."/".$videolinkdata->{body}{device}{kp_hash}."/";
        # #$hash->{videolink_int} = "http://fpdownload.adobe.com/strobe/FlashMediaPlayback_101.swf?streamType=live&autoPlay=true&playButtonOverlay=false&src=rtmp://".$videolinkdata->{body}{device}{private_ip}.":".$videolinkdata->{body}{device}{proxy_port}."/".$videolinkdata->{body}{device}{kd_hash}."/";
        # $ret .= " <a href='".$hash->{videolink_ext}."'>Play video from internet (Flash)</a>\n";
        # $ret .= " <a href='".$hash->{videolink_int}."'>Play video from local network (Flash)</a>\n";
      # }
      # else
      # {
        # $ret .= " no links available";
      # }
      # return $ret;
    # }
    # elsif( $cmd eq "updateAll" ) {
      # fitbit_poll($hash,2);
      # return undef;
    # }
    # elsif( $cmd eq "update" ) {
      # fitbit_poll($hash,1);
      # return undef;
    # }
    # elsif( $cmd eq "settings" ) {
      # fitbit_readAuraAlarm($hash);
      # return undef;
    # }
  # } elsif( $hash->{SUBTYPE} eq "ACCOUNT" ) {
    # $list = "users:noArg devices:noArg showAccount:noArg";

    # if( $cmd eq "users" ) {
      # my $users = fitbit_getUsers($hash);
      # my $ret;
      # foreach my $user (@{$users}) {
        # $ret .= "$user->{id}\t\[$user->{shortname}\]\t$user->{publickey}\t$user->{firstname} $user->{lastname}\n";
      # }

      # $ret = "id\tshort\tpublickey\t\tname\n" . $ret if( $ret );;
      # $ret = "no users found" if( !$ret );
      # return $ret;
    # }
    # if( $cmd eq "devices" ) {
      # my $devices = fitbit_getDevices($hash);
      # my $ret;
      # foreach my $device (@{$devices}) {
       # my $detail = $device->{deviceproperties};
        # $ret .= "$detail->{id}\t$device_types{$detail->{type}}\t$detail->{batterylvl}\t$detail->{sn}\n";
      # }

      # $ret = "id\ttype\t\tbattery\tSN\n" . $ret if( $ret );;
      # $ret = "no devices found" if( !$ret );
      # return $ret;
    # }
    # if( $cmd eq 'showAccount' )
    # {
      # my $username = $hash->{helper}{username};
      # my $password = $hash->{helper}{password};

      # return 'no username set' if( !$username );
      # return 'no password set' if( !$password );

      # $username = fitbit_decrypt( $username );
      # $password = fitbit_decrypt( $password );

      # return "username: $username\npassword: $password";
    # }

  # }

  # return "Unknown argument $cmd, choose one of $list";
}

sub fitbit_Set($$@) {
  my ( $hash, $name, $cmd, @arg ) = @_;
  my $list="";
  Log3 $name, 4, "$name fitbit_Set()";

  if( $hash->{SUBTYPE} eq "ACCOUNT") {
    $list = "getFriends:noArg setWeight setFat";
    if($cmd eq "getFriends") {
      #Add friends
        if( !defined( $attr{$name}{createFriends} ) ||  $attr{$name}{createFriends} eq '0' ) {
          return 'Cannot get friends. Please set attribute createFriends to 1 before executing function.';
        }

      my $friends = fitbit_getFriends($hash);


      Log3 $name, 5, "$name: fitbit_Set JSON Dump ".Dumper($friends);
      foreach my $friend (@{$friends}) {
        Log3 $name, 5, "$name: fitbit_Set JSON Dump foreach ".Dumper($friend);
        if( defined($modules{$hash->{TYPE}}{defptr}{"F$friend->{user}->{encodedId}"}) ) {
          Log3 $name, 2, "$name: friend '$friend->{user}->{encodedId}' already defined";
          next;
        }

        my $id = $friend->{user}->{encodedId};
        my $devname = "fitbit_F". $id;
        my $define= "$devname fitbit FRIEND $id";

        Log3 $name, 2, "$name: create new device '$devname' for friend '$id' $friend->{user}->{displayName}";

        my $cmdret= CommandDefine(undef,$define);
        if($cmdret) {
          Log3 $name, 1, "$name: Autocreate: An error occurred while creating user for id '$id': $cmdret";
        } else {
          $cmdret= CommandAttr(undef,"$devname alias ".$friend->{user}->{displayName});
          $cmdret= CommandAttr(undef,"$devname IODev $name");
        }
      }

    }

    if($cmd eq "setWeight") {
      return "logged weight data with log-id " . fitbit_setWeight($hash, $arg[0]);
    }

    if($cmd eq "setFat") {
      return "logged fat data with log-id " . fitbit_setFat($hash, $arg[0]);
    }

    else {
      return "Unknown argument $cmd, choose one of $list";
    }


  }
  elsif( $hash->{SUBTYPE} eq "USER") {

  }
  elsif( $hash->{SUBTYPE} eq "FRIEND") {

  }
  elsif( $hash->{SUBTYPE} eq "DEVICE") {

  }
  else {

  }

}

#Used by Subtype: ACCOUNT, USER, DEVICE, FRIEND
sub fitbit_Attr($$$) {
  my ($cmd, $name, $attrName, $attrVal) = @_;
  Log3 $name, 4, "fitbit_Attr()";

  return undef if(!defined($defs{$name}));

  my $orig = $attrVal;
  $attrVal = int($attrVal) if($attrName eq "interval");
  #comment out for debug interval < 300 seconds...
  #$attrVal = 300 if($attrName eq "interval" && $attrVal < 300 );

  if( $attrName eq "disable" ) {
    my $hash = $defs{$name};
    RemoveInternalTimer($hash);
    if( $cmd eq "set" && $attrVal ne "0" ) {
    } else {
      $attr{$name}{$attrName} = 0;
      fitbit_poll($hash,0);
    }
  }

  if( $cmd eq "set" ) {
    if( $orig ne $attrVal ) {
      $attr{$name}{$attrName} = $attrVal;
      return $attrName ." set to ". $attrVal;
    }
  }

  return;
}

sub fitbit_Notify($$) {
  # my ($hash,$dev) = @_;

  # return if($dev->{NAME} ne "global");
  # return if(!grep(m/^INITIALIZED|REREADCFG$/, @{$dev->{CHANGED}}));
  # Log3 "fitbit", 5, "fitbit: notify";

  # my $resolve = inet_aton("healthmate.withings.com");
  # if(!defined($resolve))
  # {
    # $hash->{STATE} = "DNS error";
    # InternalTimer( gettimeofday() + 3600, "fitbit_InitWait", $hash, 0);
    # return undef;
  # }


  # fitbit_initUser($hash, 0) if( $hash->{SUBTYPE} eq "USER" );
  # fitbit_connect($hash) if( $hash->{SUBTYPE} eq "ACCOUNT" );
  # fitbit_initDevice($hash) if( $hash->{SUBTYPE} eq "DEVICE" );
}

# Used by Subtype: ACCOUNT, DEVICE, USER
sub fitbit_Undefine($$) {
  my ($hash, $arg) = @_;
  Log3 "fitbit", 4, "fitbit: undefine";
  RemoveInternalTimer($hash);

  delete( $modules{$hash->{TYPE}}{defptr}{"U$hash->{USERID}"} ) if( $hash->{SUBTYPE} eq "USER" );
  delete( $modules{$hash->{TYPE}}{defptr}{"F$hash->{USERID}"} ) if( $hash->{SUBTYPE} eq "FRIEND" );
  delete( $modules{$hash->{TYPE}}{defptr}{"D$hash->{DEVICEID}"} ) if( $hash->{SUBTYPE} eq "DEVICE" );

  return undef;
}

# Used by Subtype: ACCOUNT, DEVICE, USER
sub fitbit_isDNS() {
  Log3 "fitbit", 4, "fitbit_isDNS()";
  my $resolve = inet_aton("www.fitbit.com");
  if(!defined($resolve))
  {
    Log3 "fitbit", 1, "fitbit_isDNS(): Failed to resolve www.fitbit.com";
    return undef;
  }

  $resolve = inet_aton("api.fitbit.com");
  if(!defined($resolve))
  {
    Log3 "fitbit", 1, "fitbit_isDNS(): Failed to resolve api.fitbit.com";
	return undef;
  }
  return "ok";
}

# Used by Subtype: ACCOUNT, DEVICE, USER
sub fitbit_InitWait($) {
  my ($hash) = @_;
  Log3 $hash->{NAME}, 4, "$hash->{NAME}: fitbit_InitWait()";

  RemoveInternalTimer($hash, "fitbit_InitWait");

  if(!defined( fitbit_isDNS() )) {
    readingsSingleUpdate($hash, "state", "DNS Error", 1);
    InternalTimer( gettimeofday() + 1800, "fitbit_InitWait", $hash, 0);
    return undef;
  }

  if( $init_done ) {
    Log3 "fitbit", 5, "fitbit: Init done";
    fitbit_initUser($hash, 0) if( $hash->{SUBTYPE} eq "USER" );
	  fitbit_initFriend($hash, 0) if( $hash->{SUBTYPE} eq "FRIEND" );
    fitbit_connect($hash, 0) if( $hash->{SUBTYPE} eq "ACCOUNT" );
    fitbit_initDevice($hash) if( $hash->{SUBTYPE} eq "DEVICE" );
  }
  else {
    Log3 "fitbit", 5, "fitbit: Init NOT done";
    InternalTimer(gettimeofday()+30, "fitbit_InitWait", $hash, 0);
  }
  return undef;
}

# Used by Subtype: ACCOUNT
sub fitbit_connect($;$) {
  my ($hash, $silent) = @_;
  my $name = $hash->{NAME};
  $silent = 1 if(!defined($silent));    #if InternalTimer calls this function, silent is NOT set. Don't print IODev Msg...
  Log3 $name, 4, "$name: fitbit_connect()";

  foreach my $d (keys %defs) {
    next if(!defined($defs{$d}));
    next if($defs{$d}{TYPE} ne "autocreate");
    return undef if(AttrVal($defs{$d}{NAME},"disable",undef));
  }

  my $autocreated = 0;

  #add user
  my $users = fitbit_getUsers($hash);
  foreach my $user (@{$users}) {
    readingsSingleUpdate( $hash, "state", "API ok", 1);
    if( defined($modules{$hash->{TYPE}}{defptr}{"U$user->{encodedId}"}) ) {
      Log3 $name, ($silent == 0?2:4), "$name: user '$user->{encodedId}' already defined";
      next;
    }

    my $id = $user->{encodedId};
    my $devname = "fitbit_U". $id;
    my $define= "$devname fitbit USER $id";

    Log3 $name, 2, "$name: create new device '$devname' for user '$id' $user->{displayName}";

    my $cmdret= CommandDefine(undef,$define);
    if($cmdret) {
      Log3 $name, 1, "$name: Autocreate: An error occurred while creating user for id '$id': $cmdret";
    } else {
      $cmdret= CommandAttr(undef,"$devname alias ".$user->{displayName});
      $cmdret= CommandAttr(undef,"$devname room fitbit");
      $cmdret= CommandAttr(undef,"$devname IODev $name");
      fhem("setreading $devname isFriend no", 1);

      $autocreated++;
    }
  }

  #Add friends




  my $friends = fitbit_getFriends($hash);
  Log3 $name, 5, "$name: fitbit_connect JSON Dump ".Dumper($friends);
  foreach my $friend (@{$friends}) {
    Log3 $name, 5, "$name: fitbit_connect JSON Dump foreach ".Dumper($friend);
    if( defined($modules{$hash->{TYPE}}{defptr}{"F$friend->{user}->{encodedId}"}) ) {
      Log3 $name, ($silent == 0?2:4), "$name: friend '$friend->{user}->{encodedId}' already defined";
      next;
    }

    my $id = $friend->{user}->{encodedId};
    my $devname = "fitbit_F". $id;
    my $define= "$devname fitbit FRIEND $id";

    Log3 $name, 2, "$name: create new device '$devname' for friend '$id' $friend->{user}->{displayName}";

    my $cmdret= CommandDefine(undef,$define);
    if($cmdret) {
      Log3 $name, 1, "$name: Autocreate: An error occurred while creating user for id '$id': $cmdret";
    } else {
      $cmdret= CommandAttr(undef,"$devname alias ".$friend->{user}->{displayName});
      $cmdret= CommandAttr(undef,"$devname room fitbit");
      $cmdret= CommandAttr(undef,"$devname IODev $name");
      $autocreated++;
    }
  }


  #add devices

  my $devices = fitbit_getDevices($hash);
  foreach my $device (@{$devices}) {
    if( defined($modules{$hash->{TYPE}}{defptr}{"D$device->{id}"}) ) {
       Log3 $name, ($silent == 0?2:4), "$name: device '$device->{id}' already defined";
       next;
     }

    next if( !defined($device->{id}) );

    my $id = $device->{id};
    my $devname = "fitbit_D". $id;
    my $define= "$devname fitbit DEVICE $id";

    Log3 $name, 2, "$name: create new device '$devname' for deviceID '$id' $device->{type} $device->{deviceVersion}";
    my $cmdret= CommandDefine(undef,$define);
    if($cmdret) {
      Log3 $name, 1, "$name: Autocreate: An error occurred while creating device for id '$id': $cmdret";
    } else {
       $cmdret= CommandAttr(undef,"$devname alias $device->{type} $device->{deviceVersion}");
       $cmdret= CommandAttr(undef,"$devname room fitbit");
       $cmdret= CommandAttr(undef,"$devname IODev $name");
       $autocreated++;
     }
  }

  CommandSave(undef,undef) if( $autocreated && AttrVal( "autocreate", "autosave", 1 ) );
  RemoveInternalTimer($hash, "fitbit_connect");
  InternalTimer(gettimeofday()+(6*60*60), "fitbit_connect", $hash, 0);  #every 6 hours
}

sub fitbit_autocreate($) {
  # my ($hash) = @_;
  # my $name = $hash->{NAME};
  # Log3 "fitbit", 5, "$name: autocreate";

  # $hash->{'.https'} = "https";
  # $hash->{'.https'} = "http" if( AttrVal($name, "nossl", 0) );


  # fitbit_getSessionKey( $hash );

  # my $autocreated = 0;

  # my $users = fitbit_getUsers($hash);
  # foreach my $user (@{$users}) {
    # if( defined($modules{$hash->{TYPE}}{defptr}{"U$user->{id}"}) ) {
      # Log3 $name, 2, "$name: user '$user->{id}' already defined";
      # next;
    # }
    # next if($user->{firstname} eq "Repository-User");

    # my $id = $user->{id};
    # my $devname = "fitbit_U". $id;
    # my $define= "$devname fitbit $id $user->{publickey}";

    # Log3 $name, 2, "$name: create new device '$devname' for user '$id'";

    # my $cmdret= CommandDefine(undef,$define);
    # if($cmdret) {
      # Log3 $name, 1, "$name: Autocreate: An error occurred while creating device for id '$id': $cmdret";
    # } else {
      # $cmdret= CommandAttr(undef,"$devname alias ".$user->{shortname});
      # $cmdret= CommandAttr(undef,"$devname IODev $name");
      # $cmdret= CommandAttr(undef,"$devname room fitbit");

      # $autocreated++;
    # }
  # }


  # my $devices = fitbit_getDevices($hash);
  # foreach my $device (@{$devices}) {
    # if( defined($modules{$hash->{TYPE}}{defptr}{"D$device->{deviceid}"}) ) {
      # my $d = $modules{$hash->{TYPE}}{defptr}{"D$device->{deviceid}"};
      # $d->{association} = $device->{association} if($device->{association});

      # Log3 $name, 2, "$name: device '$device->{deviceid}' already defined";
      # next;
    # }


    # my $detail = $device->{deviceproperties};
    # next if( !defined($detail->{id}) );

    # my $id = $detail->{id};
    # my $devname = "fitbit_D". $id;
    # my $define= "$devname fitbit $id";

    # Log3 $name, 2, "$name: create new device '$devname' for device '$id'";
    # my $cmdret= CommandDefine(undef,$define);
    # if($cmdret) {
      # Log3 $name, 1, "$name: Autocreate: An error occurred while creating device for id '$id': $cmdret";
    # } else {
      # $cmdret= CommandAttr(undef,"$devname alias ".$device_types{$detail->{type}}) if( defined($device_types{$detail->{type}}) );
      # $cmdret= CommandAttr(undef,"$devname alias ".$device_models{$detail->{type}}->{$detail->{model}}) if( defined($device_models{$detail->{type}}) && defined($device_models{$detail->{type}}->{$detail->{model}}) );
      # $cmdret= CommandAttr(undef,"$devname IODev $name");
      # $cmdret= CommandAttr(undef,"$devname room fitbit");

      # $autocreated++;
    # }
  # }

  # CommandSave(undef,undef) if( $autocreated && AttrVal( "autocreate", "autosave", 1 ) );
}

# Used by Subtype: DEVICE
# Called from: fitbit_Define. fitbit_InitWait
sub fitbit_initDevice($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  Log3 $name, 4, "$name: fitbit_initDevice() ".$hash->{DEVICEID};

  AssignIoPort($hash);
  if(defined($hash->{IODev}->{NAME})) {
    Log3 $name, 2, "$name: I/O device is " . $hash->{IODev}->{NAME};
  } else {
    Log3 $name, 1, "$name: no I/O device";
  }

  my $device = fitbit_getDeviceDetail( $hash );
  Log3 $name, 5, "$name: InitDevice DeviceDetails: ".Dumper($device);

  $hash->{DEVICEVERSION} = $device->[0]->{deviceVersion};
  $hash->{FITBIT_TYPE} = $device->[0]->{type};
  $hash->{DEVICEID} = $device->[0]->{id};
  $hash->{MAC} = $device->[0]->{mac};
  $hash->{DeviceType} = $device->[0]->{type};
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "lastSyncTime", $device->[0]->{lastSyncTime}, 1 );
  readingsBulkUpdateIfChanged( $hash, "batteryLevel", lc($device->[0]->{battery}), 1 );
  readingsBulkUpdateIfChanged( $hash, "state", "API ok");
  readingsEndUpdate($hash,1);

  if( !defined( $attr{$name}{stateFormat} ) ) {
    $attr{$name}{stateFormat} = "Batt. batteryLevel";
  }

  readingsSingleUpdate($hash, "state", "API ok", 1);
  InternalTimer(gettimeofday()+10, "fitbit_poll", $hash, 0);
}

# Used by Subtype: FRIEND
sub fitbit_initFriend($;$) {
  my ($hash, $silent) = @_;
  $silent = 1 if(!defined($silent));    #if InternalTimer calls this function, silent is NOT set. Don't print IODev Msg...
  my $name = $hash->{NAME};
  Log3 $name, 4, "$name: fitbit_initFriend() $hash->{USERID} silent='$silent'";

  AssignIoPort($hash);
  if(defined($hash->{IODev}->{NAME})) {
    Log3 $name, ($silent == 0?2:4), "$name: I/O device is " . $hash->{IODev}->{NAME};
  } else {
    Log3 $name, 1, "$name: no I/O device";
  }

  my $user = fitbit_getFriendDetail( $hash );
  Log3 $name, 5, "$name: fitbit_initFriend JSON Dump: ".Dumper($user);

  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "displayName", $user->{displayName}, 1 );
  readingsBulkUpdateIfChanged( $hash, "gender", $user->{gender}, 1 );
  readingsBulkUpdateIfChanged( $hash, "fullName", $user->{fullName}, 1 );
  readingsBulkUpdateIfChanged( $hash, "dateOfBirth", $user->{dateOfBirth}, 1 );
  readingsBulkUpdateIfChanged( $hash, "weight", $user->{weight}, 1 ) if($user->{weight} > 0);
  readingsBulkUpdateIfChanged( $hash, "state", "API ok");
  readingsEndUpdate($hash,1);

  $attr{$name}{stateFormat} = "weight kg" if( !defined( $attr{$name}{stateFormat} ) );
  #ToDo: stateFormat anpassen an Daten, die auch voprhanden sind.

  readingsSingleUpdate($hash, "state", "API ok", 1);
  InternalTimer(gettimeofday()+10, "fitbit_poll", $hash, 0);
  RemoveInternalTimer($hash, "fitbit_initFriend");
  InternalTimer(gettimeofday()+(6*60*60), "fitbit_initFriend", $hash, 0);  #every 6 hours
}

# Used by Subtype: USER
sub fitbit_initUser($;$) {
  my ($hash, $silent) = @_;
  my $name = $hash->{NAME};
  $silent = 1 if(!defined($silent));    #if InternalTimer calls this function, silent is NOT set. Don't print IODev Msg...
  Log3 $name, 4, "$name: fitbit_initUser() $hash->{USERID} silent='$silent'";

  AssignIoPort($hash);
  if(defined($hash->{IODev}->{NAME})) {
    Log3 $name, ($silent == 0?2:4), "$name: I/O device is " . $hash->{IODev}->{NAME};
  } else {
    Log3 $name, 1, "$name: no I/O device";
  }

  my $user = fitbit_getUserDetail( $hash );
  Log3 $name, 5, "$name: fitbit_initUser UserDetails: ".Dumper($user);

  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "displayName", $user->{displayName}, 1 );
  readingsBulkUpdateIfChanged( $hash, "gender", $user->{gender}, 1 );
  readingsBulkUpdateIfChanged( $hash, "fullName", $user->{fullName}, 1 );
  readingsBulkUpdateIfChanged( $hash, "dateOfBirth", $user->{dateOfBirth}, 1 );
  readingsBulkUpdateIfChanged( $hash, "memberSince", $user->{memberSince}, 1 );
  readingsBulkUpdateIfChanged( $hash, "weight", $user->{weight}, 1 ) if ($user->{weight} > 0);
  readingsBulkUpdateIfChanged( $hash, "state", "API ok");
  readingsEndUpdate($hash,1);

  $attr{$name}{stateFormat} .= "weight kg" if( !defined( $attr{$name}{stateFormat} ) && defined($user->{weight}) && $user->{weight} > 0 );
  #ToDO: stateFormat anpassen. weight und Steps nur dann, wenn Daten vorhanden sind.

  readingsSingleUpdate($hash, "state", "API ok", 1);
  InternalTimer(gettimeofday()+10, "fitbit_poll", $hash, 0);
  RemoveInternalTimer($hash, "fitbit_initUser");
  InternalTimer(gettimeofday()+(6*60*60), "fitbit_initUser", $hash, 0);  #every 6 hours
}

# Used by Subtype: ACCOUNT
sub fitbit_getFriends($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};


  if( !defined( $attr{$name}{createFriends} ) ||  $attr{$name}{createFriends} eq '0' ) {
    Log3 $name, 4, "$name: fitbit_getFriends Skipped loading friends as attribute 'createFriends' is not set or set to 0";
    return undef;
  }

  my $token = fitbit_decrypt( $hash->{helper}{token} );
  Log3 $name, 4, "$name: fitbit_getFriends()";

  #ToDo: Nonblocking?!
  my ($err,$data) = HttpUtils_BlockingGet({
    url => "https://api.fitbit.com/1/user/-/friends.json",
    timeout => 10,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });

  return undef if(!defined($data));

  #simulate JSON example
  #$data = '{"friends":[{"user":{"aboutMe":"I live in San Francisco.","avatar":"http://www.fitbit.com/images/profile/defaultProfile_100_male.gif","city":"San Francisco","country":"US","dateOfBirth":"1970-02-18","displayName":"Nick","encodedId":"257V3V","fullName":"Fitbit","gender":"MALE","height":176.7,"offsetFromUTCMillis":25200000,"state":"CA","strideLengthRunning":0,"strideLengthWalking":0,"timezone":"America/Los_Angeles","weight":80.5}},{"user":{"aboutMe":"","avatar":"http://www.fitbit.com/images/profile/defaultProfile_100_male.gif","city":"","country":"","dateOfBirth":"","displayName":"Fitbit U.","encodedId":"2246K9","fullName":"Fitbit User","gender":"NA","height":190.7,"offsetFromUTCMillis":14400000,"state":"","strideLengthRunning":0,"strideLengthWalking":0,"timezone":"Europe/Moscow","weight":0}}]}';

  my $json = eval { JSON->new->utf8(0)->decode($data) };
  if($@)
  {
    Log3 $name, 2, "$name: json evaluation error on fitbit_getFriends ".$@;
    return undef;
  }

  Log3 $name, 5, "$name: fitbit_getFriends JSON Dump ".Dumper($json);
  return undef if(defined(fitbit_parseJsonForError($hash, $json)));

  my @users = ();
  foreach my $user (@{$json->{friends}}) {
    #Log3 $name, 5, "$name: fitbit_getFriends JSON Dump foreach ".Dumper($user);
	  #Log3 $name, 5, "$name: fitbit_getFriends JSON Test $user->{user}->{displayName}";
	  next if( !defined($user->{user}->{encodedId}) );
    push( @users, $user );
  }
	Log3 $name, 5, "$name: fitbit_getFriends Dump ".Dumper(@users);
  return \@users;
}

# Used by Subtype: ACCOUNT
sub fitbit_getUsers($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $token = fitbit_decrypt( $hash->{helper}{token} );
  Log3 $name, 4, "$name: fitbit_getUsers()";

  #ToDo: Nonblocking?!
  my ($err,$data) = HttpUtils_BlockingGet({
    url => "https://api.fitbit.com/1/user/-/profile.json",
    timeout => 10,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });

  return undef if(!defined($data));


  my $json = eval { JSON->new->utf8(0)->decode($data) };
  if($@) {
    Log3 $name, 2, "$name: json evaluation error on getUsers ".$@;
    return undef;
  }

  Log3 $name, 5, "$name: getUsers JSON Dump ".Dumper($json);
  #xToDo: Fehlerabfangen, wenn Fitbit API mit Error antwortet!
  return undef if(defined(fitbit_parseJsonForError($hash, $json)));

  my @users = ();
  foreach my $user ($json->{user}) {
    next if( !defined($user->{encodedId}) );
    push( @users, $user );
  }

  return \@users;
}

# Used by Subtype: ACCOUNT
sub fitbit_getDevices($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};


  if( defined( $attr{$name}{createDevices} ) &&  $attr{$name}{createDevices} eq '0' ) {
	Log3 $name, 4, "$name: fitbit_getDevices Skipped loading devices as attribute 'createDevices' is set to 0";
    return undef;
  }

  my $token = fitbit_decrypt( $hash->{helper}{token} );
  Log3 $name, 4, "$name: fitbit_getDevices()";

  #ToDo: Nonblocking?
  my ($err,$data) = HttpUtils_BlockingGet({
    url => "https://api.fitbit.com/1/user/-/devices.json",
    timeout => 10,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });

  return undef if(!defined($data));

  my $json = eval { JSON->new->utf8(0)->decode($data) };
  if($@) {
    Log3 $name, 2, "$name: json evaluation error on getDevices ".$@;
    return undef;
  }
  Log3 $name, 5, "$name: fitbit_getDevices JSON Dump ".Dumper($json);
  #xToDo: Fehlerabfangen, wenn Fitbit API mit Error antwortet!
  return undef if(defined(fitbit_parseJsonForError($hash, $json)));




  my @devices = ();
  foreach my $item (@$json) {
     next if( !defined($item->{id}) );
     push( @devices, $item );
   }
  return \@devices;
}

# Used by Subtype: DEVICE
# Called from: fitbit_initDevice
# Ruft Device Daten von Fitbit an und wandelt JSON Daten in Array.
sub fitbit_getDeviceDetail($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $deviceID = $hash->{DEVICEID};

  Log3 $name, 4, "$name: fitbit_getDeviceDetail() ".$hash->{DEVICEID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getDeviceDetail(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  #ToDo: Nonblocking
  my ($err,$data) = HttpUtils_BlockingGet({
    url => "https://api.fitbit.com/1/user/-/devices.json",
    timeout => 10,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });

  Log3 $name, 5, "$name: fitbit_getDeviceDetail: HTTP Dump: ".Dumper($data);
  return undef if(!defined($data));

  my $json = eval { JSON->new->utf8(0)->decode($data) };
  if($@) {
    Log3 $name, 2, "$name: json evaluation error on getDeviceDetail ".$@;
    return undef;
  }
  Log3 $name, 5, "$name: fitbit_getDeviceDetail JSON Dump: ".Dumper($json);
  return undef if(defined(fitbit_parseJsonForError($hash, $json)));

  Log3 $name, 5, "$name: fitbit_getDeviceDetail(): Looking for DeviceID $deviceID ";

  #Look for the right device. JSON could have more than one device if there are more devices connected to account.
  my @devices = ();
  foreach my $item (@$json) {
    Log3 $name, 5, "$name: fitbit_getDeviceDetail JSON Dump: ".Dumper($item);
    Log3 $name, 5, "$name: fitbit_getDeviceDetail Found DeviceID $deviceID in Item $item->{id}" if($item->{id} eq $deviceID);
    #next if( !defined($item->{id}) );
    push( @devices, $item ) if($item->{id} eq $deviceID);
  }
  return \@devices;
}


# Used by Subtype: ACCOUNT
sub fitbit_setWeight($$) {
  my ($hash, $weight) = @_;
  my $name = $hash->{NAME};


  my $token = fitbit_decrypt( $hash->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_setWeight()";

  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
  $year = $year+1900;
  $mon = $mon+1;

  my $params = "weight=$weight&date=$year-$mon-$mday&time=$hour:$min:$sec";
  my $url = "https://api.fitbit.com/1/user/-/body/log/weight.json/";

  Log3 $name, 4, "$name: fitbit_setWeight() - Sending data to fitbit web api.";
  Log3 $name, 4, "FHEM -> fitbit URL: " . $url;
  Log3 $name, 4, "FHEM -> fitbit Params: " . $params;


  #ToDo: Nonblocking?!
  my ($err,$data) = HttpUtils_BlockingGet({
    url => $url,
    timeout => 10,
    noshutdown => 1,
    data => $params,
    method  => 'POST',
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });


  Log3 $name, 4, "$name: fitbit_setWeight() - Received data from fitbit web api.";
  Log3 $name, 4, "fitbit -> FHEM: " . $data;
  Log3 $name, 5, '$err: ' . $err;

	if (!defined($data)) {
		return undef;
	}

	my $d  = decode_json($data) if( !$err );
	Log3 $name, 5, 'Decoded: ' . Dumper($d);


    return $d->{weightLog}->{logId};

}


# Used by Subtype: ACCOUNT
sub fitbit_setFat($$) {
  my ($hash, $fat) = @_;
  my $name = $hash->{NAME};


  my $token = fitbit_decrypt( $hash->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_setFat()";

  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
  $year = $year+1900;
  $mon = $mon+1;

  my $params = "fat=$fat&date=$year-$mon-$mday&time=$hour:$min:$sec";
  my $url = "https://api.fitbit.com/1/user/-/body/log/fat.json/";

  Log3 $name, 4, "$name: fitbit_setFat() - Sending data to fitbit web api.";
  Log3 $name, 4, "FHEM -> fitbit URL: " . $url;
  Log3 $name, 4, "FHEM -> fitbit Params: " . $params;


  #ToDo: Nonblocking?!
  my ($err,$data) = HttpUtils_BlockingGet({
    url => $url,
    timeout => 10,
    noshutdown => 1,
    data => $params,
    method  => 'POST',
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });


  Log3 $name, 4, "$name: fitbit_setFat() - Received data from fitbit web api.";
  Log3 $name, 4, "fitbit -> FHEM: " . $data;
  Log3 $name, 5, '$err: ' . $err;

	if (!defined($data)) {
		return undef;
	}

	my $d  = decode_json($data) if( !$err );
	Log3 $name, 5, 'Decoded: ' . Dumper($d);


    return $d->{fatLog}->{logId};

}



# Used by Subtype: FRIEND
sub fitbit_getFriendDetail($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};
  Log3 $name, 5, "$name: fitbit_getFriendDetail() ".$hash->{USERID};
  return undef if( !defined($hash->{USERID}) );
  return undef if( $hash->{SUBTYPE} ne "FRIEND" );
  return undef if( !defined($hash->{IODev}));

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getFriendDetail(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  #ToDo: Nonblocking
  my ($err,$data) = HttpUtils_BlockingGet({
    url => "https://api.fitbit.com/1/user/-/friends.json",
    timeout => 10,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });

  #simulate JSON data example
  #$data = '{"friends":[{"user":{"aboutMe":"I live in San Francisco.","avatar":"http://www.fitbit.com/images/profile/defaultProfile_100_male.gif","city":"San Francisco","country":"US","dateOfBirth":"1970-02-18","displayName":"Nick","encodedId":"257V3V","fullName":"Fitbit","gender":"MALE","height":176.7,"offsetFromUTCMillis":25200000,"state":"CA","strideLengthRunning":0,"strideLengthWalking":0,"timezone":"America/Los_Angeles","weight":80.5}},{"user":{"aboutMe":"","avatar":"http://www.fitbit.com/images/profile/defaultProfile_100_male.gif","city":"","country":"","dateOfBirth":"","displayName":"Fitbit U.","encodedId":"2246K9","fullName":"Fitbit User","gender":"NA","height":190.7,"offsetFromUTCMillis":14400000,"state":"","strideLengthRunning":0,"strideLengthWalking":0,"timezone":"Europe/Moscow","weight":0}}]}';

  Log3 $name, 5, "$name: fitbit_getFriendDetail: HTTP Dump: ".Dumper($data);
  return undef if(!defined($data));

  my $json = eval { JSON->new->utf8(0)->decode($data) };
  if($@) {
    Log3 $name, 2, "$name: json evaluation error on getUserDetail ".$@;
    return undef;
  }

  Log3 $name, 5, "$name: fitbit_getFriendDetail JSON Dump: ".Dumper($json);
  return undef if(defined(fitbit_parseJsonForError($hash, $json)));

  #Look for the right friend. JSON response could have more than one friend
  foreach my $item (@{$json->{friends}}) {
    Log3 $name, 5, "$name: fitbit_getFriendDetail JSON Dump foreach: ".Dumper($item);
    Log3 $name, 5, "$name: fitbit_getFriendDetail Found UserID $userID in Item $item->{user}->{encodedId}" if($item->{user}->{encodedId} eq $userID);
    return $item->{user} if($item->{user}->{encodedId} eq $userID);
  }

  return undef;
}

# Used by Subtype: USER
sub fitbit_getUserDetail($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};
  Log3 $name, 4, "$name: fitbit_getUserDetail() ".$hash->{USERID};
  return undef if( !defined($hash->{USERID}) );
  return undef if( $hash->{SUBTYPE} ne "USER" );
  return undef if( !defined($hash->{IODev}));

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getUserDetail(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  #ToDo: Nonblocking
  my ($err,$data) = HttpUtils_BlockingGet({
    url => "https://api.fitbit.com/1/user/-/profile.json",
    timeout => 10,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
  });

  Log3 $name, 5, "$name: fitbit_getUserDetail: HTTP Dump: ".Dumper($data);
  return undef if(!defined($data));

  my $json = eval { JSON->new->utf8(0)->decode($data) };
  if($@) {
    Log3 $name, 2, "$name: json evaluation error on getUserDetail ".$@;
    return undef;
  }

  Log3 $name, 5, "$name: fitbit_getUserDetail JSON Dump: ".Dumper($json);
  return undef if(defined(fitbit_parseJsonForError($hash, $json)));

  return $json->{user};
}

#Called from subtype: DEVICE
sub fitbit_getDeviceProperties($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};

  Log3 $name, 4, "$name: fitbit_getDeviceProperties() ".$hash->{DEVICEID};
  return undef if( !defined($hash->{DEVICEID}) );
  return undef if( !defined($hash->{IODev}) );
  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );

  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1/user/-/devices.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'deviceProperties',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}

#Called from subtype: DEVICE
sub fitbit_getDeviceAlarms($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};

  Log3 $name, 4, "$name: fitbit_getDeviceAlarms() ".$hash->{DEVICEID};
  return undef if( !defined($hash->{DEVICEID}) );
  return undef if( !defined($hash->{IODev}) );
  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );

  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1/user/-/devices/tracker/$hash->{DEVICEID}/alarms.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'deviceAlarms',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}

# Used by Subtype: DEVICE, USER, FRIEND
sub fitbit_poll($;$) {
  my ($hash,$force) = @_;
  $force = 0 if(!defined($force));
  my $name = $hash->{NAME};

  RemoveInternalTimer($hash, "fitbit_poll");
  return undef if(AttrVal($name,"disable",0) eq "1");
  Log3 $name, 4, "$name: fitbit_poll()";

  if(!defined( fitbit_isDNS() )) {
    Log3 $name, 3, "DNS Error";
    readingsSingleUpdate($hash, "state", "DNS Error", 1);
    InternalTimer( gettimeofday() + 3600, "fitbit_poll", $hash, 0);
    return undef;
  }

  my ($now) = int(time());

  if( $hash->{SUBTYPE} eq "DEVICE" ) {
    my $interval = AttrVal($name,"interval",900);
    my $lastData = ReadingsVal( $name, ".poll", 0 );

    if(defined($hash->{FITBIT_TYPE}) && $hash->{FITBIT_TYPE} eq "TRACKER") {
      fitbit_getDeviceProperties($hash) if($force || $lastData <= ($now - $interval));
      fitbit_getDeviceAlarms($hash) if($force || $lastData <= ($now - $interval));
    } elsif(defined($hash->{FITBIT_TYPE}) && $hash->{FITBIT_TYPE} eq "SCALE") {
      fitbit_getDeviceProperties($hash) if($force || $lastData <= ($now - $interval));
    } else {
      Log3 $name, 1, "$name: fitbit_poll(): Unexpected error. Unknown fitbit device type '$hash->{FITBIT_TYPE}'. Please contact Maintainer...";
    }
  }
  elsif( $hash->{SUBTYPE} eq "FRIEND" ) {
    my $interval = AttrVal($name,"interval",900);
    my $lastData = ReadingsVal( $name, ".poll", 0 );

	fitbit_getDataFromLeaderboard($hash) if($force || $lastData <= ($now - $interval));
  }
  elsif( $hash->{SUBTYPE} eq "USER" ) {
    my $interval = AttrVal($name,"interval",900);
    my $lastData = ReadingsVal( $name, ".poll", 0 );

    fitbit_getUserDailyActivitySummary($hash) if($force || $lastData <= ($now - $interval));
    fitbit_getDataFromLeaderboard($hash) if($force || $lastData <= ($now - $interval));
    fitbit_getUserWeight($hash) if($force || $lastData <= ($now - $interval));
    fitbit_getSleepGoals($hash) if($force || $lastData <= ($now - $interval));
    fitbit_getSleepLog($hash) if($force || $lastData <= ($now - $interval));
    fitbit_getActivityHeartRate($hash) if($force || $lastData <= ($now - $interval));
  }
  else {
    Log3 $name, 1, "$name: fitbit_poll(): Unexpected error. Unknown Subtype '$hash->{SUBTYPE}'...";
  }

  InternalTimer(gettimeofday()+60, "fitbit_poll", $hash, 0);
}

#Used by Subtype: USER
sub fitbit_getSleepLog($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};

  Log3 $name, 5, "$name: fitbit_getSleepLog() ".$hash->{USERID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getSleepLog(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  my $now = substr(TimeNow(),0,10);
  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1.2/user/-/sleep/date/$now.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'sleepLog',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}

#Used by Subtype: USER
sub fitbit_getActivityHeartRate($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};

  Log3 $name, 4, "$name: fitbit_getActivityHeartRate() ".$hash->{USERID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getActivityHeartRate(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  my $now = substr(TimeNow(),0,10);
  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1/user/-/activities/heart/date/today/7d.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'activity7d',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}


#Used by Subtype: USER
sub fitbit_getSleepLog($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};

  Log3 $name, 5, "$name: fitbit_getSleepLog() ".$hash->{USERID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getSleepLog(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  my $now = substr(TimeNow(),0,10);
  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1.2/user/-/sleep/date/$now.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'sleepLog',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}




#Used by Subtype: FRIEND
sub fitbit_getDataFromLeaderboard($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};

  Log3 $name, 4, "$name: fitbit_getDataFromLeaderboard() ".$hash->{USERID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getDataFromLeaderboard(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1/user/-/friends/leaderboard.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'Leaderboard',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}

#Used by Subtype: USER
sub fitbit_getUserWeight($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};

  Log3 $name, 5, "$name: fitbit_getUserWeight() ".$hash->{USERID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getUserWeight(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  my $now = substr(TimeNow(),0,10);
  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1/user/-/body/log/weight/date/$now.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'userWeight',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}

#Used by Subtype: USER
sub fitbit_getUserDailyActivitySummary($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};
  my $userID = $hash->{USERID};

  Log3 $name, 4, "$name: fitbit_getUserDailyActivitySummary() ".$hash->{USERID};
  return undef if( !defined($hash->{IODev}) );

  my $token = fitbit_decrypt( $hash->{IODev}->{helper}{token} );
  Log3 $name, 5, "$name: fitbit_getUserDailyActivitySummary(): Use token from I/O Dev $hash->{IODev}->{NAME}";

  my $now = substr(TimeNow(),0,10);
  HttpUtils_NonblockingGet({
    url => "https://api.fitbit.com/1/user/-/activities/date/$now.json",
    timeout => 30,
    noshutdown => 1,
    header => {"Authorization" => 'Bearer '. $token, "Accept-Locale" => 'de_DE'},
    hash => $hash,
    type => 'userDailyActivitySummary',
    callback => \&fitbit_Dispatch,
  });

  $hash->{LAST_POLL} = TimeNow();
  readingsSingleUpdate( $hash, ".poll", gettimeofday(), 0 );
  return undef;
}

#Callback Routine für nonblocking HTTP. Wird durch _poll auggerufen.
#Gibt immer JSON objekt zurück, kein HTTP Dump!
sub fitbit_Dispatch($$$) {
  my ($param, $err, $data) = @_;
  my $hash = $param->{hash};
  my $name = $hash->{NAME};

  Log3 $name, 4, "$name: fitbit_Dispatch() ".$param->{type};

  if( $err ) {
    Log3 $name, 1, "$name: fitbit_Dispatch($param->{type}): http request failed: type $param->{type} - $err";
  }
  elsif( $data ) {
    $data =~ s/\n//g;
    #Log3 $name, 5, "$name: fitbit_Dispatch($param->{type}): http returned: ".Dumper($data);

    if( $data !~ /{.*}/ ) {
      Log3 $name, 1, "$name: fitbit_Dispatch($param->{type}): invalid json detected: >>$data<< " . $param->{type} if($data ne "[]");
      return undef;
    }

    my $json = eval { JSON->new->utf8(0)->decode($data) };
    if($@) {
      Log3 $name, 2, "$name: fitbit_Dispatch($param->{type}): json evaluation error on dispatch type ".$param->{type}." ".$@;
      return undef;
    }
    Log3 $name, 5, "$name: fitbit_Dispatch($param->{type}): json returned: ".Dumper($json);
    return undef if(defined(fitbit_parseHttpHeader($hash, $param->{httpheader})));

    if( $param->{type} eq 'Leaderboard' ) {
      fitbit_parseLeaderboard($hash, $json);
    }
    elsif( $param->{type} eq 'userDailyActivitySummary' ) {
      fitbit_parseUserDailyActivitySummary($hash, $json);
    }
    elsif( $param->{type} eq 'deviceAlarms' ) {
      fitbit_parseAlarms($hash, $json);
    }
    elsif( $param->{type} eq 'deviceProperties' ) {
      fitbit_parseProperties($hash, $json);
    }
    elsif( $param->{type} eq 'userWeight' ) {
      fitbit_parseUserWeight($hash, $json);
    }
    elsif( $param->{type} eq 'sleepGoals' ) {
      fitbit_parseSleepGoals($hash, $json);
    }
    elsif( $param->{type} eq 'sleepLog' ) {
      fitbit_parseSleepLog($hash, $json);
    }
    elsif( $param->{type} eq 'activity7d' ) {
      fitbit_parseActivityLog($hash, $json);
    }
  }
}

#Used by Subtype: DEVICE
sub fitbit_parseProperties($$) {
  my ($hash,$json) = @_;
  my $name = $hash->{NAME};
  my $deviceID = $hash->{DEVICEID};
  my $detail = "";
  Log3 $name, 4, "$name: fitbit_parseProperties()";

  #parse
  #Look for the right device. JSON could have more than one device if there are more devices connected to account.
  foreach my $item (@$json) {
    Log3 $name, 5, "$name: fitbit_parseProperties JSON Dump: ".Dumper($item);
    if($item->{id} eq $deviceID) {
      Log3 $name, 5, "$name: fitbit_parseProperties Found DeviceID $deviceID in Item $item->{id}";
      $detail = $item;
    }
  }

  $hash->{LAST_DATA} = TimeNow();
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "batteryLevel", lc($detail->{battery}), 1 );
  readingsBulkUpdateIfChanged( $hash, "lastSyncTime", $detail->{lastSyncTime}, 1 );

  if($detail->{battery} eq "Low" || $detail->{battery} eq "Empty") {
    readingsBulkUpdateIfChanged( $hash, "battery", lc($detail->{battery}), 1 );
  } else {
    readingsBulkUpdateIfChanged( $hash, "battery", "ok", 1 );
  }
  readingsEndUpdate($hash,1);
}

#Used by Subtype: DEVICE
sub fitbit_parseAlarms($$) {
  my ($hash,$json) = @_;
  my $name = $hash->{NAME};
  my $deviceID = $hash->{DEVICEID};
  my $detail = "";
  my $alarmCount = 0;
  my $weekDays = undef;
  Log3 $name, 4, "$name: fitbit_parseAlarms()";
  $hash->{LAST_DATA} = TimeNow();

  #parse
  #Look for the right device. JSON could have more than one device if there are more devices connected to account.
  readingsBeginUpdate($hash);
  foreach my $item (@{$json->{trackerAlarms}}) {
    $alarmCount++;
    $weekDays = undef;
    Log3 $name, 5, "$name: fitbit_parseAlarms JSON Dump: ".Dumper($item);

    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_alarmId", $item->{alarmId}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_deleted", $item->{deleted}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_enabled", $item->{enabled}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_recurring", $item->{recurring}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_snoozeCount", $item->{snoozeCount}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_snoozeLength", $item->{snoozeLength}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_syncedToDevice", $item->{syncedToDevice}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_time", $item->{time}, 1 );
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_vibe", $item->{vibe}, 1 );

    foreach my $day (@{$item->{weekDays}}) {
      Log3 $name, 5, "$name: fitbit_parseAlarms Found day $day...";
      $weekDays .= substr($day,0,2) . ",";
    }
    chop($weekDays) if(defined($weekDays));
    readingsBulkUpdateIfChanged( $hash, "alarm".$alarmCount."_weekDays", $weekDays, 1 ) if(defined($weekDays));
  }
  Log3 $name, 5, "$name: fitbit_parseAlarms There is/are $alarmCount alarm(s)...";


  readingsBulkUpdateIfChanged( $hash, "alarmCount", $alarmCount, 1 );
  readingsEndUpdate($hash,1);

  #remove old alarms....
  for(my $i=$alarmCount+1;$i<10;$i++) {
    Log3 $name, 5, "$name: fitbit_parseAlarms remove old alarm $i";
    fhem( "deletereading $name alarm".$i."_.*", 1 );
  }
}

#Used by Subtype: FRIEND, USER
sub fitbit_parseLeaderboard($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};
  my $UserID = $hash->{USERID};
  #parse
  Log3 $name, 4, "$name: fitbit_parseLeaderboard()";

  my $i = 0;
  foreach my $item (@{$json->{friends}}) {
	Log3 $name, 4, "$name: fitbit_parseLeaderboard: Contentindex $i...";
	Log3 $name, 5, "$name: fitbit_parseLeaderboard: JSON Dump $i " . Dumper($item);
	if ($item->{user}->{encodedId} eq $UserID) {
    Log3 $name, 4, "$name: fitbit_parseLeaderboard: Found content for User ID $UserID";
    $hash->{LAST_DATA} = TimeNow();
    readingsBeginUpdate($hash);
    readingsBulkUpdateIfChanged( $hash, "leaderboard_summary_steps", $item->{summary}->{steps}, 1 );
    readingsBulkUpdateIfChanged( $hash, "leaderboard_average_steps", $item->{average}->{steps}, 1 );
    readingsBulkUpdateIfChanged( $hash, "leaderboard_lifetime_steps", $item->{lifetime}->{steps}, 1 );
    readingsBulkUpdateIfChanged( $hash, "leaderboard_rank_steps", $item->{rank}->{steps}, 1 );
    readingsBulkUpdateIfChanged( $hash, "weight", $item->{user}->{weight}, 1 ) if($item->{user}->{weight} > 0);
    readingsEndUpdate($hash,1);
	  return;
	}
	$i++;
  }
  Log3 $name, 4, "$name: fitbit_parseLeaderboard: No Data found for UserID $UserID...";
  return undef;
}

#Used by Subtype: USER
sub fitbit_parseUserDailyActivitySummary($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};
  #parse
  Log3 $name, 4, "$name: fitbit_parseUserDailyActivitySummary()";

  $hash->{LAST_DATA} = TimeNow();
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "summary_steps", $json->{summary}->{steps}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_fairlyActiveMinutes", $json->{summary}->{fairlyActiveMinutes}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_marginalCalories", $json->{summary}->{marginalCalories}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_activityCalories", $json->{summary}->{activityCalories}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_caloriesBMR", $json->{summary}->{caloriesBMR}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_caloriesOut", $json->{summary}->{caloriesOut}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_sedentaryMinutes", $json->{summary}->{sedentaryMinutes}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_veryActiveMinutes", $json->{summary}->{veryActiveMinutes}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_lightlyActiveMinutes", $json->{summary}->{lightlyActiveMinutes}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_elevation", $json->{summary}->{elevation}, 1 );
  readingsBulkUpdateIfChanged( $hash, "summary_floors", $json->{summary}->{floors}, 1 );

  readingsBulkUpdateIfChanged( $hash, "goals_steps", $json->{goals}->{steps}, 1 );
  readingsBulkUpdateIfChanged( $hash, "goals_caloriesOut", $json->{goals}->{caloriesOut}, 1 );
  readingsBulkUpdateIfChanged( $hash, "goals_distance", $json->{goals}->{distance}, 1 );
  readingsBulkUpdateIfChanged( $hash, "goals_activeMinutes", $json->{goals}->{activeMinutes}, 1 );
  readingsBulkUpdateIfChanged( $hash, "goals_floors", $json->{goals}->{floors}, 1 );

  foreach my $item (@{$json->{summary}->{distances}}) {
    readingsBulkUpdateIfChanged( $hash, "summary_distances_$item->{activity}", $item->{distance}, 1 );
  }

  readingsEndUpdate($hash,1);
}

#Used by Subtype: USER
sub fitbit_parseUserWeight($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};
  #parse
  Log3 $name, 4, "$name: fitbit_parseUserWeight()";

  $hash->{LAST_DATA} = TimeNow();
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "bodyFat_fat", $json->{weight}->[0]{fat}, 1 )       if(defined($json->{weight}->[0]{fat})     && $json->{weight}->[0]{fat} > 0);
  readingsBulkUpdateIfChanged( $hash, "bodyFat_bmi", $json->{weight}->[0]{bmi}, 1 )       if(defined($json->{weight}->[0]{bmi})     && $json->{weight}->[0]{bmi} > 0);
  readingsBulkUpdateIfChanged( $hash, "bodyFat_weight", $json->{weight}->[0]{weight}, 1 ) if(defined($json->{weight}->[0]{weight})  && $json->{weight}->[0]{weight} > 0);
  readingsBulkUpdateIfChanged( $hash, "weight", $json->{weight}->[0]{weight}, 1 )         if(defined($json->{weight}->[0]{weight})  && $json->{weight}->[0]{weight} > 0);
  readingsBulkUpdateIfChanged( $hash, "bodyFat_dateTime", "$json->{weight}->[0]{date} $json->{weight}->[0]{time}", 1 ) if(defined($json->{weight}->[0]{date}) && defined($json->{weight}->[0]{time}));
  readingsEndUpdate($hash,1);
}

#Used by Subtype: USER
sub fitbit_parseSleepGoals($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};
  #parse
  Log3 $name, 4, "$name: fitbit_parseSleepGoals()";

  $hash->{LAST_DATA} = TimeNow();
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "goals_bedtime", $json->{goal}->{bedtime}, 1 ) if(defined($json->{goal}->{bedtime}));
  readingsBulkUpdateIfChanged( $hash, "goals_sleepMinDuration", $json->{goal}->{minDuration}, 1 ) if(defined($json->{goal}->{minDuration}) && $json->{goal}->{minDuration} > 0);
  readingsBulkUpdateIfChanged( $hash, "goals_wakeupTime", $json->{goal}->{wakeupTime}, 1 ) if(defined($json->{goal}->{wakeupTime}));
  readingsEndUpdate($hash,1);
}

#Used by Subtype: USER
sub fitbit_parseSleepLog($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};
  my $sleepCount = 0;
  #parse
  Log3 $name, 4, "$name: fitbit_parseSleepLog()";

  $hash->{LAST_DATA} = TimeNow();
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "sleep_summary_totalMinutesAsleep", $json->{summary}->{totalMinutesAsleep}, 1 ) if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "sleep_summary_totalSleepRecords", $json->{summary}->{totalSleepRecords}, 1 ) if($json->{summary}->{totalSleepRecords} > 0);
  readingsBulkUpdateIfChanged( $hash, "sleep_summary_totalTimeInBed", $json->{summary}->{totalTimeInBed}, 1 ) if($json->{summary}->{totalTimeInBed} > 0);

  readingsBulkUpdateIfChanged( $hash, "sleep_summary_total_minutes_deep", $json->{summary}->{stages}->{deep}, 1 ) if($json->{summary}->{stages}->{deep} > 0);
  readingsBulkUpdateIfChanged( $hash, "sleep_summary_total_minutes_light", $json->{summary}->{stages}->{light}, 1 ) if($json->{summary}->{stages}->{light} > 0);
  readingsBulkUpdateIfChanged( $hash, "sleep_summary_total_minutes_rem", $json->{summary}->{stages}->{rem}, 1 ) if($json->{summary}->{stages}->{rem} > 0);
  readingsBulkUpdateIfChanged( $hash, "sleep_summary_total_minutes_wake", $json->{summary}->{stages}->{wake}, 1 ) if($json->{summary}->{stages}->{wake} > 0);

  foreach my $item (@{$json->{sleep}}) {
    $sleepCount++;
    Log3 $name, 5, "$name: fitbit_parseSleepLog JSON Dump: ".Dumper($item);

    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_efficiency", $item->{efficiency}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_duration", $item->{duration}/1000/60, 1 );    #convert milisec. to min.
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_endTime", $item->{endTime}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_isMainSleep", $item->{isMainSleep}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_minutesAfterWakeup", $item->{minutesAfterWakeup}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_minutesAsleep", $item->{minutesAsleep}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_minutesAwake", $item->{minutesAwake}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_minutesToFallAsleep", $item->{minutesToFallAsleep}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_startTime", $item->{startTime}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_timeInBed", $item->{timeInBed}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_type", $item->{type}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_deepsleep_count", $item->{levels}->{summary}->{deep}->{count}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_deepsleep_minutes", $item->{levels}->{summary}->{deep}->{minutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_deepsleep_30DayAvg", $item->{levels}->{summary}->{deep}->{thirtyDayAvgMinutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_remsleep_count", $item->{levels}->{summary}->{rem}->{count}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_remsleep_minutes", $item->{levels}->{summary}->{rem}->{minutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_remsleep_30DayAvg", $item->{levels}->{summary}->{rem}->{thirtyDayAvgMinutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_lightsleep_count", $item->{levels}->{summary}->{light}->{count}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_lightsleep_minutes", $item->{levels}->{summary}->{light}->{minutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_lightsleep_30DayAvg", $item->{levels}->{summary}->{light}->{thirtyDayAvgMinutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_wake_count", $item->{levels}->{summary}->{wake}->{count}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_wake_minutes", $item->{levels}->{summary}->{wake}->{minutes}, 1 );
    readingsBulkUpdateIfChanged( $hash, "sleep".$sleepCount."_summary_wake_30DayAvg", $item->{levels}->{summary}->{wake}->{thirtyDayAvgMinutes}, 1 );


  }
  Log3 $name, 4, "$name: fitbit_parseSleepLog There is/are $sleepCount sleep(s)...";

  #remove old sleeps....
  for(my $i=$sleepCount+1;$i<10;$i++) {
    Log3 $name, 5, "$name: fitbit_parseSleepLog remove old sleep $i";
    fhem( "deletereading $name sleep".$i."_.*", 1 );
  }
  readingsEndUpdate($hash,1);
}


#Used by Subtype: USER
sub fitbit_parseActivityLog($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};

  Log3 $name, 4, "$name: fitbit_parseActivityLog()";

  $hash->{LAST_DATA} = TimeNow();
  Log3 $name, 5, "$name: fitbit_parseActivityLog JSON Dump: ".Dumper($json);
  readingsBeginUpdate($hash);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_outofrange_minutes", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[0]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_outofrange_min", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[0]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_outofrange_max", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[0]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_outofrange_calories", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[0]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_fatburn_minutes", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[1]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_fatburn_min", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[1]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_fatburn_max", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[1]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_fatburn_calories", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[1]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_cardio_minutes", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[2]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_cardio_min", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[2]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_cardio_max", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[2]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_cardio_calories", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[2]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);


  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_peak_minutes", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[3]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_peak_min", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[3]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_peak_max", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[3]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_peak_calories", $json->{'activities-heart'}[0]->{value}->{heartRateZones}[3]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_today_resting_heartrate", $json->{'activities-heart'}[0]->{value}->{restingHeartRate}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_outofrange_minutes", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[0]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_outofrange_min", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[0]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_outofrange_max", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[0]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_outofrange_calories", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[0]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_fatburn_minutes", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[1]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_fatburn_min", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[1]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_fatburn_max", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[1]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_fatburn_calories", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[1]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_cardio_minutes", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[2]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_cardio_min", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[2]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_cardio_max", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[2]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_cardio_calories", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[2]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_peak_minutes", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[3]->{minutes}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_peak_min", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[3]->{min}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_peak_max", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[3]->{max}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);
  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_peak_calories", $json->{'activities-heart'}[1]->{value}->{heartRateZones}[3]->{caloriesOut}, 1 ); # if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsBulkUpdateIfChanged( $hash, "activity_hr_yesterday_resting_heartrate", $json->{'activities-heart'}[1]->{value}->{restingHeartRate}, 1 ); #if($json->{summary}->{totalMinutesAsleep} > 0);

  readingsEndUpdate($hash,1);
}


#Check if JSON hat an "error" Item
sub fitbit_parseJsonForError($$) {
  my ($hash, $json) = @_;
  my $name = $hash->{NAME};
  my ($errorType, $errorMsg) = undef;

  Log3 $name, 4, "$name: fitbit_parseHttpDataError()";
  #Log3 $name, 5, "$name: fitbit_parseHttpDataError: JSON Dump: " . Dumper($json);

  if (ref($json) eq 'HASH') {
    if (defined($json->{errors}->[0])) {
      $errorType = $json->{errors}->[0]->{errorType} if(defined($json->{errors}->[0]->{errorType}));
      $errorMsg = $json->{errors}->[0]->{message} if(defined($json->{errors}->[0]->{message}));
      Log3 $name, 1, "$name: fitbit_parseHttpDataError: Found error '$errorType' in JSON reply with msg '$errorMsg'";
      readingsSingleUpdate($hash, "state", "API Error. See FHEM Log for more details", 1);
      return "error";
    }
  }

  return undef;
}

# Read the fitbit API Rate-Limit and write it to reading of I/O Device
# see also: https://dev.fitbit.com/docs/basics/#hitting-the-rate-limit
sub fitbit_parseHttpHeader($$) {
  my ($hash, $header) = @_;
  my $name = $hash->{NAME};
  my ($iodevName, $limit, $remaining, $reset) = undef;

  Log3 $name, 4, "$name: fitbit_ParseHttpHeader()";
  #Log3 $name, 5, "$name: fitbit_ParseHttpHeader: $header";

  if(defined($hash->{IODev}->{NAME})) {
    Log3 $name, 4, "$name: fitbit_ParseHttpHeader: I/O device is " . $hash->{IODev}->{NAME};
	$iodevName = $hash->{IODev}->{NAME};
  } else {
    Log3 $name, 4, "$name: fitbit_ParseHttpHeader: no I/O device";
  }

  #Look for error 401
  if ($header =~ /HTTP\/1\.1 (401).*/) {
    Log3 $name, 1, "$name: fitbit_parseHttpHeader: HTTP 401 (Unauthorized) found. Maybe a wrong token?";
    return "error";
  }

  #Fitbit-Rate-Limit-Limit: The quota number of calls.
  if ($header =~ /Fitbit-Rate-Limit-Limit: (\d*)/) {
    $limit = $1;
    #Log3 $name, 4, "$name: fitbit_parseHttpHeader: $1";
  }

  #Fitbit-Rate-Limit-Remaining: The number of calls remaining before hitting the rate limit.
  if ($header =~ /Fitbit-Rate-Limit-Remaining: (\d*)/) {
    $remaining = $1;
    #Log3 $name, 4, "$name: fitbit_parseHttpHeader: $1";
  }

  #Fitbit-Rate-Limit-Reset: The number of seconds until the rate limit resets.
  if ($header =~ /Fitbit-Rate-Limit-Reset: (\d*)/) {
    $reset = $1;
    #Log3 $name, 4, "$name: fitbit_parseHttpHeader: $1";
  }

  fhem("setreading $iodevName rateLimitLimit $limit", 1) if(defined($iodevName) && defined($limit));
  fhem("setreading $iodevName rateLimitRemaining $remaining", 1) if(defined($iodevName) && defined($remaining));
  fhem("setreading $iodevName rateLimitReset $reset", 1) if(defined($iodevName) && defined($reset));


  if ($remaining > 1 ) {
	return undef;
  } else {
    Log3 $name, 1, "$name: fitbit_ParseHttpHeader: ERROR. Rate-Limit exceeded. You have to wait $reset seconds...";
	fhem("setreading $iodevName state API Error. See FHEM Log for more details", 1);
	return "error";
  }
}

 sub fitbit_encrypt($) {
   my ($decoded) = @_;
   my $key = getUniqueId();
   my $encoded;

   return $decoded if( $decoded =~ /crypt:/ );

   for my $char (split //, $decoded) {
     my $encode = chop($key);
     $encoded .= sprintf("%.2x",ord($char)^ord($encode));
     $key = $encode.$key;
   }

   return 'crypt:'.$encoded;
 }

 sub fitbit_decrypt($) {
   my ($encoded) = @_;
   my $key = getUniqueId();
   my $decoded;

   return $encoded if( $encoded !~ /crypt:/ );

   $encoded = $1 if( $encoded =~ /crypt:(.*)/ );

   for my $char (map { pack('C', hex($_)) } ($encoded =~ /(..)/g)) {
     my $decode = chop($key);
     $decoded .= chr(ord($char)^ord($decode));
     $key = $decode.$key;
   }

   return $decoded;
 }


 1;

=pod
=item device
=item summary fitbit health data for users, friends and devices
=begin html

<a name="fitbit"></a>
<h3>fitbit</h3>
<ul>
  FHEM module for fitbit devices.<br><br>

  Notes:
  <ul>
    <li>JSON and Digest::SHA have to be installed on the FHEM host. </li>
  </ul><br>

  <a name="fitbit_Define"></a>
  <b>Define</b>
  <ul>
    <b><code>define &lt;name&gt; fitbit ACCOUNT &lt;token&gt;</code></b><br>
    <code>define &lt;name&gt; fitbit USER &lt;User ID&gt;</code><br>
    <code>define &lt;name&gt; fitbit FRIEND &lt;User ID&gt;</code><br>
    <code>define &lt;name&gt; fitbit DEVICE &lt;Device ID&gt;</code><br>
    <br>

    Defines a FHEM device of the choosen fitbit subtype ACCOUNT, USER, FRIEND or DEVICE.<br><br>
    If a fitbit device of the ACCOUNT type is created all fhem devices for users, friends and devices are automaticaly created.<br>
    You need one ACCOUNT device, at least. The ACCOUNT device is acting as I/O Device.
    <br>

    Examples:
    <ul>
      <code>define fitbit_IO fitbit ACCOUNT ueilkdalksdj9210394iujre2qwmiaksjd...</code><br>
    </ul>
  </ul><br>

  <a name="fitbit_Readings"></a>
  <b>Readings</b>
  <ul>
    <li>isFriend - USER, FRIEND - </li>
    <li>state - ALL SUBTYPES - Shows if there is an API or DNS error.</li>
    <li>lastSyncTime - DEVICE - Last time the fitbit device has synced with fitbit</li>
    <li>batteryLevel - DEVICE - Level of battery: High, Middle, Low or Empty</li>
    <li>displayName - USER, FRIEND - Name (identical with reading fullName)</li>
    <li>fullName - USER, FRIEND - Name (identical with reading displayName)</li>
    <li>gender - USER, FRIEND - Gender of User</li>
    <li>dateOfBirth - USER, FRIEND - Date of birth</li>
    <li>weight - USER, FRIEND - Weight from Leaderboard(USER and FRIEND) or fitbit weight log (USER)</li>
    <li>memberSince</li>

    <li>battery - DEVICE - Indicator if the batteryLevel is low or empty</li>
    <li>alarm&lt;id&gt;_alarmId - DEVICE - Internal ID to identify the alarm timer</li>
    <li>alarm&lt;id&gt;_deleted - DEVICE - </li>
    <li>alarm&lt;id&gt;_enabled - DEVICE - </li>
    <li>alarm&lt;id&gt;_recurring - DEVICE - Shows if the alarm is recurring</li>
    <li>alarm&lt;id&gt;_snoozeCount - DEVICE - How often the alarm will snooze </li>
    <li>alarm&lt;id&gt;_snoozeLength - DEVICE - Length of snooze in minutes</li>
    <li>alarm&lt;id&gt;_syncedToDevice - DEVICE - Shows if the alarm is synced to tracker</li>
    <li>alarm&lt;id&gt;_time - DEVICE - Time to alert</li>
    <li>alarm&lt;id&gt;_vibe - DEVICE - </li>
    <li>alarmCount - DEVICE - How many alarms are configured for this device</li>

    <li>leaderboard_summary_steps - USER, FRIEND - Leaderboard summary of steps from the last 7 days</li>
    <li>leaderboard_average_steps - USER, FRIEND - The daily average steps calculated from the past</li>
    <li>leaderboard_lifetime_steps - USER, FRIEND - </li>
    <li>leaderboard_rank_steps - USER, FRIEND - Leaderboard rank position</li>

    <li>summary_steps - USER - </li>
    <li>summary_fairlyActiveMinutes - USER - </li>
    <li>summary_marginalCalories - USER - </li>
    <li>summary_activityCalories - USER - </li>
    <li>summary_caloriesBMR - USER - </li>
    <li>summary_caloriesOut - USER - </li>
    <li>summary_sedentaryMinutes - USER - </li>
    <li>summary_veryActiveMinutes - USER - </li>
    <li>summary_lightlyActiveMinutes - USER - </li>

    <li>goals_steps - USER - </li>
    <li>goals_caloriesOut - USER - </li>
    <li>goals_distance - USER - </li>
    <li>goals_activeMinutes - USER - </li>
    <li>summary_distances_ - USER - </li>
    <li>goals_bedtime - USER - </li>
    <li>goals_sleepMinDuration - USER - </li>
    <li>goals_wakeupTime - USER - </li>

    <li>bodyFat_fat - USER - </li>
    <li>bodyFat_bmi - USER - </li>
    <li>bodyFat_weight - USER - </li>
    <li>bodyFat_dateTime - USER - </li>
    <li>summary_distances_ - USER - </li>

    <li>sleep&lt;id&gt;_efficiency - USER - </li>
    <li>sleep&lt;id&gt;_duration - USER - </li>
    <li>sleep&lt;id&gt;_endTime - USER - </li>
    <li>sleep&lt;id&gt;_isMainSleep - USER - </li>
    <li>sleep&lt;id&gt;_minutesAfterWakeup - USER - </li>
    <li>sleep&lt;id&gt;_minutesAsleep - USER - </li>
    <li>sleep&lt;id&gt;_minutesAwake - USER - </li>
    <li>sleep&lt;id&gt;_minutesToFallAsleep - USER - </li>
    <li>sleep&lt;id&gt;_startTime - USER - </li>
    <li>sleep&lt;id&gt;_timeInBed - USER - </li>
    <li>sleep&lt;id&gt;_type - USER - </li>
    <li>sleep&lt;id&gt;_summary_asleepCount - USER - </li>
    <li>sleep&lt;id&gt;_summary_asleepMinutes - USER - </li>
    <li>sleep&lt;id&gt;_summary_awakeCount - USER - </li>
    <li>sleep&lt;id&gt;_summary_awakeMinutes - USER - </li>
    <li>sleep&lt;id&gt;_summary_restlessCount - USER - </li>
    <li>sleep&lt;id&gt;_summary_restlessMinutes - USER - </li>
    <li>sleep_summary_totalMinutesAsleep - USER - </li>
    <li>sleep_summary_totalSleepRecords - USER - </li>
    <li>sleep_summary_totalTimeInBed - USER - </li>
  </ul><br>

  <a name="fitbit_Set"></a>
  <b>Set</b>
  <ul>
    <li>getFriends (ACCOUNT)<br>
      Search new friends</li>
  </ul><br>

  <a name="fitbit_Attr"></a>
  <b>Attributes</b>
  <ul>
    <li>interval<br>
      the interval in seconds used to check for new values. Minimum 300 seconds</li>
    <li>disable<br>
      1 -> stop polling</li>
  </ul>
</ul>

=end html
=cut
