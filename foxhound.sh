#!/usr/bin/env bash
_scriptDir="$(dirname `readlink -f $0`)"

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit 1
fi

function Info {
  echo -e -n '\e[7m'
  echo "$@"
  echo -e -n '\e[0m'
}

function Error {
  echo -e -n '\e[41m'
  echo "$@"
  echo -e -n '\e[0m'
}

if [ -r unattended.txt ] ; then
	. unattended.txt
else

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
fi


Info  "Creating directories"
mkdir -p /nsm
mkdir -p /nsm/pcap/
mkdir -p /nsm/scripts/
mkdir -p /nsm/bro/
mkdir -p /nsm/bro/extracted/
if [ ! -d /opt/ ]; then
	mkdir -p /opt/
fi

function install_packages()
{
Info "Installing Required .debs"
apt-get update && apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev ssmtp htop vim libgeoip-dev ethtool git tshark tcpdump nmap mailutils python-pip autoconf libtool pkg-config libnacl-dev libncurses5-dev libnet1-dev libcli-dev libnetfilter-conntrack-dev liburcu-dev

	if [ $? -ne 0 ]; then
		Error "Error. Please check that apt-get can install needed packages."
		exit 2;
	fi
} 

function install_geoip()
{
Info "Installing GEO-IP"
	wget  http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz 
	wget  http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz 
	gunzip GeoLiteCity.dat.gz 
	gunzip GeoLiteCityv6.dat.gz 
	mv GeoLiteCity* /usr/share/GeoIP/
	ln -s /usr/share/GeoIP/GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
	ln -s /usr/share/GeoIP/GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat 
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
	cd $_scriptDir
	cp nic.sh /etc/network/if-up.d/interface-tuneup
	chmod +x /etc/network/if-up.d/interface-tuneup
	ifconfig eth0 down && ifconfig eth0 up
} 

function install_netsniff() 
{
Info "Installing Netsniff-NG PCAP"
	touch /etc/netsniff
	apt-get -y install netsniff-ng
	cd $_scriptDir
	mv cleanup.sh /nsm/scripts/cleanup
	chmod +x /nsm/scripts/cleanup
} 

function create_service_netsniff() 
{
Info "Creating Netsniff-NG service"
echo "[Unit]
Description=Netsniff-NG PCAP
After=network.target

[Service]
ExecStart=/usr/local/sbin/netsniff-ng --in eth0 --out /nsm/pcap/ --bind-cpu 3 -s --interval 100MiB
Type=simple
EnvironmentFile=-/etc/netsniff

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
mailhub=$smtp_server:587
hostname=foxhound
FromLineOverride=YES
UseTLS=NO
UseSTARTTLS=YES
AuthUser=$smtp_user
AuthPass=$smtp_pass" \ > /etc/ssmtp/ssmtp.conf
}


function install_loki() 
{
Info "Installing YARA packages"
	# Info "Installing Pylzma"
	#	cd /opt/
	#	wget  https://pypi.python.org/packages/fe/33/9fa773d6f2f11d95f24e590190220e23badfea3725ed71d78908fbfd4a14/pylzma-0.4.8.tar.gz 
	#	tar -zxvf pylzma-0.4.8.tar.gz
	#	cd pylzma-0.4.8/
	#	python ez_setup.py 
	#	python setup.py 
	# Info "Installing YARA"
		# git clone  https://github.com/VirusTotal/yara.git /opt/yara
		# cd /opt/yara
		# ./bootstrap.sh 
		# ./configure 
		# make && make install 
	Info "Installing PIP LOKI Packages"
		pip install psutil
		pip install yara-python
		pip install gitpython
		pip install pylzma
		pip install netaddr
	Info "Installing LOKI"
		git clone  https://github.com/Neo23x0/Loki.git /nsm/Loki
		git clone  https://github.com/Neo23x0/signature-base.git /nsm/Loki/signature-base/ 
		echo "export PATH=/nsm/Loki:$PATH" >> /etc/profile
		chmod +x /nsm/Loki/loki.py
echo "
#!/bin/sh
/usr/bin/python /nsm/Loki/loki.py --noprocscan --dontwait --onlyrelevant -p /nsm/bro/extracted -l /nsm/Loki/log
" \ > /nsm/scripts/scan
chmod +x /nsm/scripts/scan
}

function install_bro() 
{
Info "Installing Bro"
	apt-get -y install bro broctl bro-pkg bro-common bro-aux 
	# cd /opt/
		# wget  https://www.bro.org/downloads/release/bro-2.4.1.tar.gz 
		# wget  https://www.bro.org/downloads/bro-2.5.2.tar.gz
		# tar -xzf bro-2.5.2.tar.gz
	# cd bro-2.5.2 
		# ./configure --localstatedir=/nsm/bro/
		# make -j 4 
		# make install 
	# Info "Setting Bro variables"
	# echo "export PATH=/usr/local/bro/bin:$PATH" >> /etc/profile
	# source ~/.bashrc
}

function install_criticalstack() 
{
Info "Installing Critical Stack Agent"
		# wget  http://intel.criticalstack.com/client/critical-stack-intel-arm.deb 
		# dpkg -i critical-stack-intel-arm.deb 
		curl https://packagecloud.io/install/repositories/criticalstack/critical-stack-intel/script.deb.sh | sudo bash
		apt-get install critical-stack-intel
		chown critical-stack:critical-stack /usr/share/bro/site/local.bro
		sudo -u critical-stack critical-stack-intel config --set bro.path=/usr/bin/bro
		sudo -u critical-stack critical-stack-intel config --set bro.include.path=/usr/share/bro/site/local.bro
		sudo -u critical-stack critical-stack-intel config --set bro.broctl.path=/usr/bin/broctl
		sudo -u critical-stack critical-stack-intel api $api 
		# rm critical-stack-intel-arm.deb
		sudo -u critical-stack critical-stack-intel list
		sudo -u critical-stack critical-stack-intel pull
		#Deploy and start BroIDS
		export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/bro/bin:\$PATH"
	echo "Deploying and starting BroIDS"
		broctl deploy
		broctl cron enable
		#Create update script
echo "
echo \"#### Pulling feed update ####\"
sudo -u critical-stack critical-stack-intel pull
echo \"#### Applying the updates to the bro config ####\"
broctl check
broctl install
echo \"#### Restarting bro ####\"
broctl restart
python /nsm/Loki/loki.py --update
" \ > /nsm/scripts/update
		sudo chmod +x /nsm/scripts/update
}

function install_bro_reporting() 
{
Info "Bro Reporting Requirements"
#PYSUBNETREE
	cd /opt/
	git clone  git://git.bro-ids.org/pysubnettree.git 
	cd pysubnettree/
	python setup.py install 
#IPSUMDUMP
	cd /opt/
	wget http://www.read.seas.harvard.edu/~kohler/ipsumdump/ipsumdump-1.85.tar.gz 
	tar -zxvf ipsumdump-1.85.tar.gz
	cd ipsumdump-1.85/
	./configure && make && make install 
}

function config_bro_scripts() 
{
Info "Configuring BRO scripts"
	#PULL BRO SCRIPTS
	cd /usr/share/bro/site/
	if [ -d /usr/share/bro/site/bro-scripts/ ]; then
		rm -rf /usr/share/bro/site/bro-scripts/
	fi
	mkdir -p /usr/share/bro/site/bro-scripts
	git clone https://github.com/sneakymonk3y/bro-scripts.git 
	echo "@load bro-scripts/geoip"  >> /usr/share/bro/site/local.bro
	echo "@load bro-scripts/extract"  >> /usr/share/bro/site/local.bro
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
echo "0-59/5 * * * * root /nsm/scripts/cleanup" >> /etc/crontab
echo "00 7/19 * * *  root /nsm/scripts/update" >> /etc/crontab
#echo "0-59/5 * * * * root python /nsm/scripts/scan" >> /etc/crontab 

echo "
    ______           __  __                      __
   / ____/___  _  __/ / / /___  __  ______  ____/ /
  / /_  / __ \| |/_/ /_/ / __ \/ / / / __ \/ __  / 
 / __/ / /_/ />  </ __  / /_/ / /_/ / / / / /_/ /  
/_/    \____/_/|_/_/ /_/\____/\__,_/_/ /_/\__,_/   
-  B     L     A     C     K     B     O     X  -

" \ > /etc/motd                                                                 
echo "foxhound" > /etc/hostname
echo "127.0.0.1		foxhound" >> /etc/hosts
Info "Please reboot"
