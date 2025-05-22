#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

import subprocess
import ipaddress
import csv

SPECIAL_PURPOSE_ADDRESS ='\
0 16777215 Reserved:arin\n\
167772160 184549375 Reserved:arin\n\
1681915904 1686110207 Reserved:arin\n\
2130706432 2147483647 Reserved:arin\n\
2851995648 2852061183 Reserved:arin\n\
2886729728 2887778303 Reserved:arin\n\
3221225472 3221225727 Reserved:arin\n\
3221225984 3221226239 Reserved:arin\n\
3223307264 3223307519 Reserved:arin\n\
3224682752 3224683007 Reserved:arin\n\
3227017984 3227018239 Reserved:arin\n\
3232235520 3232301055 Reserved:arin\n\
3232706560 3232706815 Reserved:arin\n\
3323068416 3323199487 Reserved:arin\n\
3325256704 3325256959 Reserved:arin\n\
3405803776 3405804031 Reserved:apnic\n\
4026531840 4294967295 Reserved\n\
4294967295 4294967295 Reserved\n'

SPECIAL_PURPOSE_ASN ='\
0,Reserved:ripe\n\
1,arin\n\
112,Reserved:arin\n\
113,arin\n\
23456,Reserved:arin\n\
23457,arin\n\
64496,Reserved:ripe\n\
131072,apnic\n\
4200000000,Reserved:ripe\n'

DOWNLOAD_IP_COMMAND = '\
loc=("lacnic" "ripe" "arin" "afrinic" "apnic");\
rirs=("lacnic" "ripencc" "arin" "afrinic" "apnic");\
for i in ${!rirs[*]};\
do \
url="https://ftp."${loc[$i]}".net/pub/stats/"${rirs[$i]}"/delegated-"${rirs[$i]}"-extended-latest";\
echo "$url";\
wget -q "$url";\
cat "delegated-"${rirs[$i]}"-extended-latest" | grep "ipv4" | awk \'BEGIN { FS = "|"} ; {print $4","$5","$1}\' | tail -n +2 >> csv_tmp;\
rm -f "delegated-"${rirs[$i]}"-extended-latest";\
done'

DOWNLOAD_ASN_COMMAND = '\
wget -q https://www.iana.org/assignments/as-numbers/as-numbers-1.csv;\
wget -q https://www.iana.org/assignments/as-numbers/as-numbers-2.csv;\
cat as-numbers-1.csv | tr " " ","  | egrep "ARIN|APNIC|RIPE|AFRINIC|LACNIC" | awk \'BEGIN { FS = ","} ; {print $1","tolower($4)}\' >> asn_tmp;\
cat as-numbers-2.csv | tr " " ","  | egrep "ARIN|APNIC|RIPE|AFRINIC|LACNIC|Unallocated" | awk \'BEGIN { FS = ","} ; {if ($2 == "Unallocated")print $1","$2; else print $1","tolower($4);}\' >> asn_tmp;\
rm -f as-numbers-1.csv as-numbers-2.csv'

SORT_UNIQ_COMMAND_IPV4 = 'cat trans_tmp | sort -n -k 1,1 | tr " " ","  > nerd-whois-ipv4.csv'
SORT_UNIQ_COMMAND_ASN = 'cat asn_tmp2 | tr ","  " " | sort -n -k1,1 | uniq -f 1 | tr " " "," > nerd-whois-asn.csv'

CLEANUP_COMMAND = 'rm -f csv_tmp trans_tmp asn_tmp asn_tmp2'

print("Downloading list of IP block allocations from FTP servers...")

subprocess.call(DOWNLOAD_IP_COMMAND, shell=True, executable='/bin/bash')

r = open('csv_tmp', 'r')
w = open('trans_tmp', 'w')
datareader = csv.reader(r, delimiter=',')

print("Converting IP representation to long uint...")

for row in datareader:
	rir = 'ripe' if row[2] == "ripencc" else row[2]
	first_ip = int(ipaddress.ip_address(row[0]))
	last_ip = first_ip + int(row[1]) - 1
	w.write(str(first_ip) + ' ' + str(last_ip) + ' ' + rir + '\n')

w.write(SPECIAL_PURPOSE_ADDRESS)
r.close()
w.close()

print("Removing duplicities...")

subprocess.call(SORT_UNIQ_COMMAND_IPV4, shell=True, executable='/bin/bash')

print("Downloading ASN allocation tables from IANA...")

subprocess.call(DOWNLOAD_ASN_COMMAND, shell=True, executable='/bin/bash')

r = open('asn_tmp', 'r')
w = open('asn_tmp2', 'w')
datareader = csv.reader(r, delimiter=',')

for row in datareader:
	asn = row[0].split('-')
	w.write(asn[0] + ',' + row[1] + '\n')

w.write(SPECIAL_PURPOSE_ASN)
r.close()
w.close()

print("Cleaning up temporary files...")

subprocess.call(SORT_UNIQ_COMMAND_ASN, shell=True, executable='/bin/bash')
subprocess.call(CLEANUP_COMMAND, shell=True, executable='/bin/bash')

print('Done!')
