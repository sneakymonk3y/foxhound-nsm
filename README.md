# FOXHOUND-NSM

RaspberryPi 3 NSM based on [Bro](https://www.bro.org). Suitable for a home 'blackbox' deployment.

``` bash
root@foxhound:~# git clone https://github.com/sneakymonk3y/foxhound-nsm.git
root@foxhound:~# chmod +x ~/foxhound-nsm/foxhound.sh
root@foxhound:~# cd foxhound-nsm
root@foxhound:~# ./foxhound.sh
```

### Requirements
* [Raspberry Pi 3](https://thepihut.com/products/raspberry-pi-3-model-b) or ARM based system.
* [Raspbian Lite](https://www.raspberrypi.org/downloads/raspbian/)
* Switch with port mirroring capability, e.g:
  * [NetGear Gigabit Switch](https://www.amazon.co.uk/dp/B002YPJ8KM)
  * [MicroTik RouterBoard 260GS](https://www.amazon.com/dp/B00GAZ2HHS)
  * [Security Onion's Device List](https://github.com/Security-Onion-Solutions/security-onion/wiki/Hardware#packets)
* [Critical Stack Account](https://intel.criticalstack.com/user/sign_up)
* optional: [Mailgun Account] (http://www.mailgun.com/)
