#!/usr/bin/env bash
RED='\033[0;31m' #store literal color value for red
GRN='\033[0;32m' #store literal color value for green
NC='\033[0m' # no color
bold=$(tput bold) #variable to format text as bold
normal=$(tput sgr0) #variable to format text as normal

cd /home/$USER/Downloads/ #change to current users downloads folder
mostRecent=$(ls -t | head -n1) #store the most recently downloaded file as variable
echo '================================'
printf "${GRN}Downloads Folder Hash/Filename\n${NC}"
echo '================================'
for file in *; do #for each file in d/l folder
	md5sum "$file" #extract the md5hash
done | sed 's/  /+,/' | awk -F"+" '{print $1, $2, $3}' | sed 's/ ,/,/g' #formatting make output csv friendly

echo '================================'
printf "${GRN}Most Recent File: ${NC}"
md5sum $mostRecent #extract md5sum of most recent d/l file

echo '================================'
VTHash=$(md5sum $(ls -t | head -n1) | awk '{print $1}') #store md5hash of most recently d/l file as variable
#echo Hash to be scanned: $VTHash
printf "${GRN}VirusTotal Summary:${NC}"
#Post hash to VT
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey="63c74add1fbcb18cd03e860185b2716cc6f756071f698674d7ab125d5e38840d" --form resource=$VTHash | awk -F 'positives\":' '{printf "\nVT Hits: " $2}' | awk -F ' ' '{print $1$2$3$6$7}' | sed 's|["}]||g' 
echo '================================'
read -n 1 -s -r -p "Press any key to generate full VirusTotal Report..."
echo""
printf "${GRN}Full VirusTotal Report:${NC}"
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey="63c74add1fbcb18cd03e860185b2716cc6f756071f698674d7ab125d5e38840d" --form resource=$VTHash | sed 's|\},|\}\n|g'
echo ""

#| awk '{print $644,$645}'
#| awk -F 'positives\":' '{print "VT Hits" $2}' | awk -F ' ' '{print $1$2$3$6$7}' | sed 's|["}]||g'
#| sed 's|\},|\}\n|g'
#| sed 's/\t/,|,/g' | column -s ',' -t
#API Token: 63c74add1fbcb18cd03e860185b2716cc6f756071f698674d7ab125d5e38840d
#VT Test:
#md5sum $(ls -t | head -n1) | awk '{print $1}'