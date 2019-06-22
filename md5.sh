#!/usr/bin/env bash
RED='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m'
bold=$(tput bold)
normal=$(tput sgr0)
cd /home/$USER/Downloads/
mostRecent=$(ls -t | head -n1)
echo '--------------------------------'
printf "${GRN}Downloads Folder Hash/Filename\n${NC}"
echo '--------------------------------'
for file in *; do
	md5sum "$file"
done | sed 's/  /+,/' | awk -F"+" '{print $1, $2, $3}' | sed 's/ ,/,/g'
echo '--------------------------------'
printf "${GRN}Most Recent File: ${NC}"
md5sum $mostRecent
echo '--------------------------------'
VTHash=$(md5sum $(ls -t | head -n1) | awk '{print $1}')
printf "${GRN}VirusTotal Summary:${NC}"
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey="YOUR_API_TOKEN_HERE" --form resource=$VTHash | awk -F 'positives\":' '{printf "\nVT Hits: " $2}' | awk -F ' ' '{print $1$2$3$6$7}' | sed 's|["}]||g' 
echo '--------------------------------'
read -n 1 -s -r -p "Press any key to generate full VirusTotal Report..."
printf "\n"
printf "${GRN}Full VirusTotal Report:${NC}"
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey="YOUR_API_TOKEN_HERE" --form resource=$VTHash | sed 's|\},|\}\n|g'
printf "\n"

#| awk '{print $644,$645}'
#| awk -F 'positives\":' '{print "VT Hits" $2}' | awk -F ' ' '{print $1$2$3$6$7}' | sed 's|["}]||g'
#| sed 's|\},|\}\n|g'
#| sed 's/\t/,|,/g' | column -s ',' -t
#API Token: 63c74add1fbcb18cd03e860185b2716cc6f756071f698674d7ab125d5e38840d
#VT Test:
#md5sum $(ls -t | head -n1) | awk '{print $1}'
