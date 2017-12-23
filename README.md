# FOXHOUND-NSM

RaspberryPi 3 NSM based on [Bro](https://www.bro.org). Suitable for a home 'blackbox' deployment.

## Requirements
* [Raspberry Pi 3](https://thepihut.com/products/raspberry-pi-3-model-b) or ARM based system.
* [Raspbian Lite](https://www.raspberrypi.org/downloads/raspbian/)
* Switch with port mirroring capability, e.g:
  * [NetGear GS105Ev2](https://www.amazon.co.uk/dp/B002YPJ8KM)
  * [MicroTik RouterBoard 260GS](https://www.amazon.com/dp/B00GAZ2HHS)
  * [Security Onion's Device List](https://github.com/Security-Onion-Solutions/security-onion/wiki/Hardware#packets)
* [Critical Stack Account](https://intel.criticalstack.com/user/sign_up)
* optional: [Mailgun Account](http://www.mailgun.com/)
* optional: [WD PiDrive Foundation Edition](http://wdlabs.wd.com/category/wd-pidrive/)

## General Preparation
* critical stack:
  * get a critical [stack account](https://intel.criticalstack.com/user/sign_up)
  * set up a collection and a sensor
  * add feeds to your collection
  * note down sensor API key
* not down parameters for email server

## Prepare Pi
* download [Raspian Lite](https://www.raspberrypi.org/downloads/raspbian/) and [put onto micro SD card](https://www.raspberrypi.org/documentation/installation/installing-images/README.md)
* create empty file `ssh` on boot file system of SD card
* connect LAN cable to Pi (make sure DHCP works)
* optionally: connect WD PiDrive to Pi
* boot Pi, ssh into devivce
* change password for user pi (`passwd`)
* sudo to root (`sudo su -`) and use `raspi-config` to
  * set up WLAN (Network Options)
  * expand filesystem (Advanced Options)
  * exit, don't reboot yet
* check if you can ssh into Pi using the WLAN IP of the Pi
* optionally: prepare PiDrice ([see Hints below](#hints))
* reboot (`reboot`)
* detach LAN cable

## Install Foxhound
* connect to Pi using WLAN IP
* update base OS:
```
sudo su -
apt-get update
apt-get -y -u dist-upgrade
```
* install git: `apt-get -y install git`
* change into root's home directory: `cd`
* clone repository: `git clone https://github.com/sneakymonk3y/foxhound-nsm.git`
* prepare installation:
```
cd foxhound-nsm
chmod +x foxhound.sh
```
* optionally: copy unattended-sample.txt to unattended.txt and adopt to your needs
* begin installation: `./foxhound.sh`
* shuwdon device: `shutdown -h now`

## Start Sniffing
* configure switch (set up port mirroring)
* plug switch into your home LAN on a suitable spot
* connect switch mirror port with Pi
* power up Pi and see if it works as expected ([see e.g. Further Reading below](further-reading))

## Hints
* the script isn't meant to be run multiple times on one installation (yet), so to get reliable results you should use a fresh OS SD card (and erase `/nsm` if using PiDrive) when re-running the script
* use cheap micro SD card for OS, e.g. 8 GB ones (get multiple and have one ready with current Raspbian distro)
* use separate file systeem for `/nsm`, e.g. [Western Digital PiDrive Foundation Edition](http://wdlabs.wd.com/category/wd-pidrive/)
  * delete existing partitions
  * create primary partition and label it, e.g. `NSM`
  * format with ext4, e.g. `mkfs.ext4 /dev/sda1`
  * mount into `/nsm`, e.g. add `LABEL=NSM /nsm ext4 defaults 0 0` to `/etc/fstab` and `mkdir /nsm && mount /nsm`

## To Do
* adopt script so it can be run multiple times in a row without creating strange side effects
* add logging and error handling to script

## Further Reading
* [Foxhound: Blackbox - A RaspberryPi 3 NSM (Network Security Monitor) based on Bro, Netsniff-NG, Loki and Critical Stack.](https://www.sneakymonkey.net/2016/10/30/raspberrypi-nsm/)
