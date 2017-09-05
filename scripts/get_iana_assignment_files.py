#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

import subprocess
import ipaddress
import csv

SPECIAL_PURPOSE_ADDRESS ='\
0,Reserved\n\
167772160 Reserved:arin\n\
184549376 arin\n\
1681915904 Reserved:arin\n\
1686110208 arin\n\
2130706432 Reserved:arin\n\
2147483648 ripe\n\
2851995648 Reserved:arin\n\
2852061184 afrinic\n\
2886729728 Reserved:arin\n\
2887778304 arin\n\
3221225472 Reserved:arin\n\
3221225728 Reserved\n\
3221225984 Reserved:arin\n\
3221226240 arin\n\
3223307264 Reserved:arin\n\
3223307520 apnic\n\
3224682752 Reserved:arin\n\
3224683008 arin\n\
3227017984 Reserved:arin\n\
3227018240 arin\n\
3232235520 Reserved:arin\n\
3232301056 arin\n\
3232706560 Reserved:arin\n\
3232706816 arin\n\
3323068416 Reserved:arin\n\
3323199488 arin\n\
3325256704 Reserved:arin\n\
3325256960 apnic\n\
3405803776 Reserved:apnic\n\
3405804032 apnic\n\
4026531840 Reserved\n'

DOWNLOAD_IP_COMMAND = '\
loc=("lacnic" "ripe" "arin" "afrinic" "apnic");\
rirs=("lacnic" "ripencc" "arin" "afrinic" "apnic");\
for i in ${!rirs[*]};\
do \
wget "ftp://ftp."${loc[$i]}".net/pub/stats/"${rirs[$i]}"/delegated-"${rirs[$i]}"-extended-latest";\
cat "delegated-"${rirs[$i]}"-extended-latest" | grep "ipv4" | awk \'BEGIN { FS = "|"} ; {print $4","$1}\' | tail -n +2 >> csv_tmp;\
rm -f "delegated-"${rirs[$i]}"-extended-latest";\
done'

DOWNLOAD_ASN_COMMAND = '\
wget https://www.iana.org/assignments/as-numbers/as-numbers-1.csv;\
wget https://www.iana.org/assignments/as-numbers/as-numbers-2.csv;\
cat as-numbers-1.csv | tr " " ","  | egrep "ARIN|APNIC|RIPE|AFRINIC|LACNIC" | awk \'BEGIN { FS = ","} ; {print $1","tolower($4)}\' >> asn_tmp;\
cat as-numbers-2.csv | tr " " ","  | egrep "ARIN|APNIC|RIPE|AFRINIC|LACNIC" | awk \'BEGIN { FS = ","} ; {print $1","tolower($4)}\' >> asn_tmp;\
rm -f as-numbers-1.csv as-numbers-2.csv'

SORT_UNIQ_COMMAND = 'cat trans_tmp | sort -n -k 1,1 | uniq -f 1 | tr " " ","  > nerd-whois-ipv4.csv'

CLEANUP_COMMAND = 'rm -f csv_tmp trans_tmp asn_tmp'

print("Downloading list of IP block allocations from FTP servers...")

p = subprocess.call(DOWNLOAD_IP_COMMAND, shell=True, executable='/bin/bash')

r = open('csv_tmp', 'r')
w = open('trans_tmp', 'w')
datareader = csv.reader(r, delimiter=',')

print("Converting IP representation to long uint...")

for row in datareader:
	rir = 'ripe' if row[1] == "ripencc" else row[1]
	w.write(str(int(ipaddress.ip_address(row[0]))) + ' ' + rir + '\n')

w.write(SPECIAL_PURPOSE_ADDRESS)
r.close()
w.close()

print("Removing duplicities...")

subprocess.call(SORT_UNIQ_COMMAND, shell=True, executable='/bin/bash')

print("Downloading ASN allocation tables from IANA...")

p = subprocess.call(DOWNLOAD_ASN_COMMAND, shell=True, executable='/bin/bash')

r = open('asn_tmp', 'r')
w = open('nerd-whois-asn.csv', 'w')
datareader = csv.reader(r, delimiter=',')

for row in datareader:
	asn = row[0].split('-')
	w.write(asn[0] + ',' + row[1] + '\n')

r.close()
w.close()

print("Cleaning up temporary files...")

p = subprocess.call(CLEANUP_COMMAND, shell=True, executable='/bin/bash')

print('Done!')
