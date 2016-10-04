##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Load the scan detection script.
@load misc/scan

# Log some information about web applications being used by users
# on your network.
@load misc/app-stats

# Detect traceroute being run on the network.
@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
                                                                                                34,1          Top
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
# @load protocols/ssl/notary

# If you have libGeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
#@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
#@load frameworks/files/detect-MHR

# Critical Stack, Inc - https://intel.criticalstack.com
@load /opt/critical-stack/frameworks/intel

# Evernote scripts
@load bro-scripts/human
@load bro-scripts/ssl-ext-san
@load bro-scripts/exfil
@load bro-scripts/notice-ext

# Exfiltration
redef Exfil::file_of_whitelisted_hostnames = "/usr/local/bro/share/bro/site/input/whitelists/hostnames.whitelist";
redef Exfil::file_of_whitelisted_subnets = "/usr/local/bro/share/bro/site/input/whitelists/subnets.whitelist";
# DNS zones to whitelist
# define here instead of using the input framework becuase we can't reliably load a table before bro_init completes
# and converting this to a regex requires bro_init.
redef Exfil::common_zones = {
    #".zombo.com", # Welcome to zombocom
}

# Flow
# single conn Tx bytes over which we want to alert on immediately
redef Exfil::flow_bytes_tx_to_notice= 20000000;
# destination hosts to record if over this many bytes
redef Exfil::flow_bytes_tx_to_log_and_track= 1000000;
# number of large uploads per IP before an email is generated for that IP
redef Exfil::count_of_tracked_flows_to_notice = 13;
# how long to suppress re-notices
redef Exfil::flow_suppression_interval = 480mins;
# flow producer consumer ratio floor
redef Exfil::min_flow_producer_consumer_ratio = 0.4;

# DNS
redef Exfil::query_interval = 1min;
redef Exfil::queries_per_query_interval = 800.0;
redef Exfil::query_length_sum_per_interval = 10000.0;
redef Exfil::txt_answer_types_per_interval = 5.0;
redef Exfil::null_answer_types_per_interval = 1.0;
redef Exfil::frequent_queriers = {
    # A cool host
    10.0.0.1/32,
    # A cool net
    192.168.1.0/24,
    };


# ICMP
redef Exfil::icmp_interval = 1min;
redef Exfil::icmp_per_query_interval = 60.0;
redef Exfil::frequent_icmp_senders = {
    # A cool host
    10.0.0.1/32,
    # A cool net
    192.168.1.0/24,
};

# Notices

# Use notice_ext for emailed alert types
redef Notice::ext_emailed_types = {
    Exfil::Large_Flow,
    Exfil::DNS_Excessive_Query_Velocity,
    Exfil::DNS_Excessive_Query_Length,
    Exfil::DNS_too_many_TXT_Answers,
    Exfil::DNS_too_many_NULL_Answers,
    Exfil::FTP_Upload,
    Exfil::ICMP_Velocity,
    Exfil::SSH,
};
