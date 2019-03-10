# FHEM-fitbit

Basis for this repository is the module written by TeeVaau and posted in FHEM forum community.
The original forum thread is available here:
  https://forum.fhem.de/index.php/topic,73285.0.html
As the latest update on the module was in September 2017 and I wanted to implement some additional functionality I decided to modify the existing code. The modified code is available in this repository.

Many thanks to TeeVau as most of the implementation effort was spent by him.

To use the module the following perl extensions must be installed:

 - libdigest-hmac-perl
 - libjson-perl
 - libposix-strptime-perl

As reported by forum users missing perl extensions may cause a crash of your FHEM installation.
 
The module uses the fitbit web API which has some security requirements.
As a result the setup of the fitbit FHEM module requires some additional steps to grant access to the fitbit data before it can be used.
The steps have been described by TeeVau in his first post in the FHEM forum:
    https://forum.fhem.de/index.php/topic,73285.0.html
