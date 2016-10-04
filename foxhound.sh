echo "Please enter your Critical Stack API Key: "
read cs_api

apt-get update
apt-get -y upgrade

#NTOP PFRING LOAD BALANCING
#NO SUPPORT FOR ARM as of 03/10/2016

#GEOIP
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
gunzip GeoLiteCity.dat.gz
gunzip GeoLiteCityv6.dat.gz
mv GeoLiteCity* /usr/share/GeoIP/
ln -s /usr/share/GeoIP/GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
ln -s /usr/share/GeoIP/GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat

#PACKAGES
sudo apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
sudo apt-get -y install sendmail htop vim libgeoip-dev ethtool git tshark tcpdump nmap

#DISBALE IPV6
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sed -i '1 s/$/ ipv6.disable=1/' /boot/cmdline.txt
sysctl -p

#CONFIGURE NETWORK OPTIONS
echo "
	#!/bin/bash
	for i in rx tx gso gro; do ethtool -K eth0 $i off; done;
	ifconfig eth0 promisc
	ifconfig eth0 mtu 9000
	exit 0
	" \ >  /etc/network/if-up.d/interface-tuneup
chmod +x /etc/network/if-up.d/interface-tuneup

#PCAP - TBC
#SNORT/SURICATA - TBC

#INSTALL BRO
sudo wget https://www.bro.org/downloads/release/bro-2.4.1.tar.gz
sudo tar -xzf bro-2.4.1.tar.gz
cd bro-2.4.1 
sudo ./configure --prefix=/usr/local/bro
sudo make -j 4
sudo make install

#SET VARIABLES
echo "export PATH=/usr/local/bro/bin:\$PATH" >> /etc/profile

#Install Critical Stack
echo "Installing Critical Stack Agent"
sudo wget http://intel.criticalstack.com/client/critical-stack-intel-arm.deb
sudo dpkg -i critical-stack-intel-arm.deb
sudo -u critical-stack critical-stack-intel api $cs_api 
sudo rm critical-stack-intel-arm.deb
sudo -u critical-stack critical-stack-intel list
sudo -u critical-stack critical-stack-intel pull

#Deploy and start BroIDS
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/bro/bin:\$PATH"
echo "Deploying and starting BroIDS"
sudo -i broctl check
sudo -i broctl deploy


echo "
	sudo -u critical-stack critical-stack-intel config
	echo \"#### Pulling feed update ####\"
	sudo -u critical-stack critical-stack-intel pull
	echo \"#### Applying the updates to the bro config ####\"
	broctl check
	broctl install
	echo \"#### Restarting bro ####\"
	broctl restart
" \ > /opt/criticalstack_update
sudo chmod +x /opt/criticalstack_update

#PULL BRO SCRIPTS
mkdir /opt/bro/
mkdir /opt/bro/extracted/
cd /usr/local/bro/share/bro/site/
git clone https://github.com/sneakymonk3y/bro-scripts.git
echo "@load bro-scripts/geoip"  >> /usr/local/bro/share/bro/site/local.bro
echo "@load bro-scripts/file-extraction"  >> /usr/local/bro/share/bro/site/local.bro
echo "@load bro-scripts/user-agent-length"  >> /usr/local/bro/share/bro/site/local.bro
broctl check
broctl deploy

#CRON JOBS
echo "0-59/5 * * * * root /usr/local/bro/bin/broctl cron" >> /etc/crontab
echo "00 7/19 * * *  root sh /opt/criticalstack_update" >> /etc/crontab

echo "

███████╗ ██████╗ ██╗  ██╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
██╔════╝██╔═══██╗╚██╗██╔╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
█████╗  ██║   ██║ ╚███╔╝ ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══╝  ██║   ██║ ██╔██╗ ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██║     ╚██████╔╝██╔╝ ██╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
  
" \ > /etc/motd                                                                 
echo "foxhound" > /etc/hostname


