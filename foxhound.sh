#!/usr/bin/env bash
export BINDIR="${BINDIR-/usr/bin}"

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit 1
fi

# Load support functions
_scriptDir="$(dirname `readlink -f $0`)"
source lib.sh

echo "Please enter your Critical Stack API Key: "
read api
echo "Please enter your SMTP server"
read smtp_server
echo "Please enter your SMTP user"
read smtp_user
echo "Please enter your SMTP password"
read smtp_pass
echo "Please enter your notification email"
read notification

Info  "Creating directories"
mkdir -p /nsm
mkdir -p /nsm/pcap/
mkdir -p /nsm/scripts/
mkdir -p /nsm/bro/
mkdir -p /nsm/bro/extracted/

function install_geoip()
{
Info "Installing GEO-IP"
	wget -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz 
	wget -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz 
	gunzip GeoLiteCity.dat.gz 
	gunzip GeoLiteCityv6.dat.gz 
	mv GeoLiteCity* /usr/share/GeoIP/
	ln -s /usr/share/GeoIP/GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
	ln -s /usr/share/GeoIP/GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat 
} 

function install_packages()
{
Info "Installing Required .debs"
apt-get update && apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev ssmtp htop vim libgeoip-dev ethtool git tshark tcpdump nmap mailutils 

	if [ $? -ne 0 ]; then
		Error "Error. Please check that apt-get can install needed packages."
		exit 2;
	fi
} 

function config_net_ipv6()
{
Info "Disabling IPv6"
	echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	sed -i '1 s/$/ ipv6.disable_ipv6=1/' /boot/cmdline.txt
	sysctl -p
} 

function config_net_opts()
{
Info "Configuring network options"
	echo "
		#!/bin/bash
		for i in rx tx gso gro; do ethtool -K eth0 $i off; done;
		ifconfig eth0 promisc
		ifconfig eth0 mtu 9000
		exit 0
	" \ >  /etc/network/if-up.d/interface-tuneup
	chmod +x /etc/network/if-up.d/interface-tuneup
	ifconfig eth0 down && ifconfig eth0 up
} 

function install_netsniff() 
{
Info "Installing Netsniff-NG PCAP"
	touch /etc/netsniff-ng
	git clone -q https://github.com/netsniff-ng/netsniff-ng.git /opt/
	cd netsniff-ng
	./configure && make && make install 
} 

function create_service_netsniff() 
{
Info "Creating Netsniff-NG service"
		echo "[Unit]
		Description=Netsniff-NG PCAP
		After=network.target

		[Service]
		ExecStart=/usr/local/sbin/netsniff-ng --in eth0 --out /nsm/pcap/ --bind-cpu 3 -s --interval 100MiB --prefix=foxhound-
		Type=simple
		EnvironmentFile=-/etc/netsniff-ng

		[Install]
		WantedBy=multi-user.target" > /etc/systemd/system/netsniff-ng.service
	systemctl enable netsniff-ng
	systemctl daemon-reload
	service netsniff-ng start
} 
 
function config_ssmtp() 
{
Info "Configuring SSMTP"
		echo "
		root=$notification
		mailhub=$smtp_server
		hostname=foxhound
		FromLineOverride=YES
		UseTLS=YES
		UseSTARTTLS=YES
		AuthUser=$smtp_user
		AuthPass=$smtp_pass" \ > /etc/ssmtp/ssmtp.conf
}


function install_loki() 
{
Info "Installing YARA packages"
	apt-get -y install pip gcc python-dev python-pip autoconf libtool
	Info "Installing Pylzma"
		cd /opt/
		wget -q https://pypi.python.org/packages/fe/33/9fa773d6f2f11d95f24e590190220e23badfea3725ed71d78908fbfd4a14/pylzma-0.4.8.tar.gz 
		tar -zxvf pylzma-0.4.8.tar.gz
		cd pylzma-0.4.8/
		python ez_setup.py 
		python setup.py 
	Info "Installing YARA"
		git clone -q https://github.com/VirusTotal/yara.git /opt/
		cd /opt/yara
		./bootstrap.sh 
		./configure 
		make && make install 
	Info "Installing PIP LOKI Packages"
		pip install psutil
		pip install yara-python
		pip install gitpython
		pip install pylzma
		pip install netaddr
	Info "Installing LOKI"
		git clone -q https://github.com/Neo23x0/Loki.git /nsm/
		git clone -q https://github.com/Neo23x0/signature-base.git /nsm/Loki 
		chmod +x /nsm/Loki/loki.py
}

function install_bro() 
{
Info "Installing Bro"
	cd /opt/
		wget -q https://www.bro.org/downloads/release/bro-2.4.1.tar.gz 
		tar -xzf bro-2.4.1.tar.gz
	cd bro-2.4.1 
		./configure --localstatedir=/nsm/bro/
		make -j 4 
		make install 
	Info "Setting Bro variables"
	echo "export PATH=/usr/local/bro/bin:\$PATH" >> /etc/profile
}

function install_criticalstack() 
{
Info "Installing Critical Stack Agent"
		wget -q http://intel.criticalstack.com/client/critical-stack-intel-arm.deb 
		dpkg -i critical-stack-intel-arm.deb 
		sudo -u critical-stack critical-stack-intel api $api 
		rm critical-stack-intel-arm.deb
		sudo -u critical-stack critical-stack-intel list
		sudo -u critical-stack critical-stack-intel pull
		#Deploy and start BroIDS
		export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/bro/bin:\$PATH"
	echo "Deploying and starting BroIDS"
		broctl check
		broctl deploy
		broctl cron enable
		#Create update script
	echo "
		sudo -u critical-stack critical-stack-intel config
		echo \"#### Pulling feed update ####\"
		sudo -u critical-stack critical-stack-intel pull
		echo \"#### Applying the updates to the bro config ####\"
		broctl check
		broctl install
		echo \"#### Restarting bro ####\"
		broctl restart
	" \ > /nsm/scripts/criticalstack_update
		sudo chmod +x /nsm/scripts/criticalstack_update
}

function install_bro_reporting() 
{
Info "Bro Reporting Requirements"
#PYSUBNETREE
	cd /opt/
	git clone git://git.bro-ids.org/pysubnettree.git 
	cd pysubnettree/
	python setup.py install 
#IPSUMDUMP
	cd /opt/
	wget -q http://www.read.seas.harvard.edu/~kohler/ipsumdump/ipsumdump-1.85.tar.gz 
	tar -zxvf ipsumdump-1.85.tar.gz
	cd ipsumdump-1.85/
	./configure && make && make install 
}

function config_bro_scripts() 
{
Info "Configuring BRO scripts"
	#PULL BRO SCRIPTS
	cd /usr/local/bro/share/bro/site/
	if [ ! -d /usr/local/bro/share/bro/site/bro-scripts/ ]; then
		rm -rf /usr/local/bro/share/bro/site/bro-scripts/
	fi
	git clone https://github.com/sneakymonk3y/bro-scripts.git 
	echo "@load bro-scripts/geoip"  >> /usr/local/bro/share/bro/site/local.bro
	echo "@load bro-scripts/extract"  >> /usr/local/bro/share/bro/site/local.bro
	if broctl check | grep -q ' ok'; then
	  broctl status
	else Error "bro-script check failed"
	fi
	broctl deploy
}

install_geoip
install_packages
config_net_ipv6
config_net_opts
install_netsniff
create_service_netsniff
config_ssmtp
install_loki
install_bro
install_criticalstack
install_bro_reporting
config_bro_scripts

#CRON JOBS
echo "0-59/5 * * * * root /usr/local/bro/bin/broctl cron" >> /etc/crontab
echo "00 7/19 * * *  root /nsm/scripts/criticalstack_update" >> /etc/crontab
echo "0-59/5 * * * * root /nsm/Loki/loki.py -p /opt/bro/extracted/ --noprocscan --printAll --dontwait " >> /etc/crontab 

echo "
    ______           __  __                      __
   / ____/___  _  __/ / / /___  __  ______  ____/ /
  / /_  / __ \| |/_/ /_/ / __ \/ / / / __ \/ __  / 
 / __/ / /_/ />  </ __  / /_/ / /_/ / / / / /_/ /  
/_/    \____/_/|_/_/ /_/\____/\__,_/_/ /_/\__,_/   
-  B     L     A     C     K     B     O     X  -

" \ > /etc/motd                                                                 
echo "foxhound" > /etc/hostname