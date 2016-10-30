#!/bin/sh

FS='/nsm/pcap'
FREE=1000000

checkdf() {
  local used
  used=`df -k ${FS} | tail -1 | awk '{ print $4 }'`
  if [ ${used} -ge ${FREE} ]; then
    exit 0
  fi
}

checkdf

cd /nsm/
for f in `find /nsm/pcap/ -type f \( -name '*.pcap' \) -exec basename {} \; | sort -n -t\. -k3`; do
  echo "  deleting " `ls -lash /nsm/pcap/${f}`
  rm -f /nsm/pcap/${f}
  checkdf
done
exit 0