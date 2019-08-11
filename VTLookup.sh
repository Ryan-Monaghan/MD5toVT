#!/usr/bin/env bash
RED='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m'
bold=$(tput bold)
normal=$(tput sgr0)
VTAPIToken=
help="\n${bold}Hash Extract\n\n${bold}NAME\n - ${normal}./md5.sh - Extracts the MD5 Hash values for each file in the Downloads folder, then generates a VirusTotal report for your most recently downloaded file.\n\n${bold}SYNOPSIS\n./md5.sh ${normal}\e[4m[FILE]\e[0m\n${bold}e.g. - ${normal}./md5 [-h]\n\n${bold}DESCRIPTION\n - ${normal}"
cd /home/$USER/Downloads/
for file in *; do
	find -name "* *" -type f | rename 's/ /_/g'
done
mostRecent="$(ls -t | head -n1)"

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
	printf "$help" #print the help menu to the screen
exit 1 #force exit script
elif [ "$VTAPIToken" == "" ] || [ "$VTAPIToken" == " " ]; then
	printf "${RED}ERROR:${NC} No API key detected. Fetch your API key from: https://www.virustotal.com/gui/user/<YOURUSERNAME>/apikey\n" #print the help menu to the screen
exit 1 #force exit script
fi
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
printf "${GRN}${bold}Downloads Folder Hash/Filename\n${normal}${NC}"
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
for file in *; do
	md5sum "$file"
done | sed 's/  /+,/' | awk -F"+" '{print $1, $2, $3}' | sed 's/ ,/,/g'
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
printf "${GRN}${bold}Most Recent File:\n${NC}"
md5sum "$mostRecent"
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
VTHash=$(md5sum $(ls -t | head -n1) | awk '{print $1}')
printf "${GRN}${bold}VirusTotal Summary:\n${normal}${NC}"
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey=$VTAPIToken --form resource=$VTHash | awk -F 'positives\":' '{printf "\nVT Hits: " $2}' | awk -F ' ' '{print $1$2$3$6$7}' | sed 's|["}]||g' 
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
read -n 1 -s -r -p "Press any key to generate full VirusTotal Report..."
printf "\n"
printf "${GRN}${bold}Full VirusTotal Report:\n${normal}${NC}"
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey=$VTAPIToken --form resource=$VTHash | sed 's|\},|\}\n|g' | column -t -s "," | sed 's/detected//g' | sed 's/version//g' | sed 's/"//g' | sed 's/"//g' | sed 's/{//g' | sed 's/://g' | sed 's/true//g' | sed 's/false//g' | sed 's/result//g' | sed 's/}//g' | sed 's/scans//g' | sed 's/null/NoResult/g' | sed 's/update//g' | sed 's/v //g' | sed 's/-- //g' | sed 's/AB //g' | sed 's/- //g' | sed 's/a //g' | sed 's/variant //g' | sed 's/of //g' | sed 's/( //g' | sed 's/eff //g' | sed 's/ )//g' | sed 's/) //g' | sed 's/(high //g' | sed 's/confidence) //g' | sed 's/ confidence)//g' | sed 's/of //g' | sed 's/(ai //g' | sed 's/score= //g' | sed 's/(A //g' | sed 's/(CLOUD //g' | sed 's/(W //g' | sed 's/confidence //g' | sed 's/ Malicious PE/Malicious PE/g' | sed 's/ PE/PE/g' | sed 's/[[:digit:]]\+\.//g' | sed 's/[0-9]//g' | sed 's/- //g' | sed 's/-- //g' | sed 's/ -//g'  | sed 's/v //g' | sed 's/AB //g' | column -t -s " " #| awk -F '{print $1}' #| sed 's/"//g' | sed 's/{//g' | sed 's/ /|/g'| sed 's/://g' | sed 's/detected//g' | sed 's/,//g' | sed 's/version//g' | sed 's/true//g' | sed 's/false//g' | sed 's/}//g' 
#printf "\n"
