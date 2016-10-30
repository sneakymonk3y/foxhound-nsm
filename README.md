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
* [Raspbian Lite](https://www.raspberrypi.org/documentation/installation/installing-images/mac.md)
* [NetGear Gigabit Switch](https://www.amazon.co.uk/NETGEAR-GS105E-200UKS-ProSAFE-Managed-Ethernet/dp/B002YPJ8KM) or similiar that supports port mirroring.
* [Critical Stack Account](https://intel.criticalstack.com/user/sign_up)
* [Mailgun Account] (http://www.mailgun.com/)
