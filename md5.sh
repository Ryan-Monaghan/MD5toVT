#!/usr/bin/env bash
RED='\033[0;31m' #stores value of red
GRN='\033[0;32m' #stores value of green
NC='\033[0m' #reverts text back to original colour
bold=$(tput bold) #stores value for bold
normal=$(tput sgr0) #reverts text to normal/unbold
#stores users vt api token
VTAPIToken=63c74add1fbcb18cd03e860185b2716cc6f756071f698674d7ab125d5e38840d
#stores help menu
help="\n${bold}Hash Extract\n\n${bold}NAME\n - ${normal}./md5.sh - Extracts the MD5 Hash values for each file in the Downloads folder, then generates a VirusTotal report for your most recently downloaded file.\n\n${bold}SYNOPSIS\n./md5.sh ${normal}\e[4m[FILE]\e[0m\n${bold}e.g. - ${normal}./md5 [-h]\n\n${bold}DESCRIPTION\n - ${normal}"
#stores value of most recent d/l file
mostRecent="$(ls -t | head -n1)"
#change to users d/l folder on script launch
cd /home/$USER/Downloads/

for file in *; do #for each file in d/l folder
	#search for whitespace, and replace with '_'
	find -name "* *" -type f | rename 's/ /_/g' 
done

if [ "$1" == "-c" ] || [ "$1" == "--csv" ]; then
	
	if ["$2" == ""] || ["$2" == " "]; then
		printf "${RED}${bold}ERROR:${NC}${normal} No file name given. Please see -h or --help for usage.\n"
		exit 1 #force exit script
	else
		for file in *; do #for each file in d/l folder
		#dig out md5sum of each file
		md5sum "$file"
		#sed used to make output csv friendly
		done | sed 's/  /+,/' | awk -F"+" '{print $1, $2, $3}' | sed 's/ ,/,/g' > "/home/$USER/Desktop/$2"
		exit 1 #force exit script
	fi
fi

#if the script is invoked with the -h or --help parameter
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
	#display help menu
	printf "$help" #print the help menu to the screen
	exit 1 #force exit script

#else, if the user has not entered a vt api
elif [ "$VTAPIToken" == "" ] || [ "$VTAPIToken" == " " ]; then
	#prompt them to do so
	printf "${RED}${bold}ERROR:${NC}${normal} No API key detected.Fetch your API key from:\nhttps://www.virustotal.com/gui/user/<YOURUSERNAME>/apikey\n" #print the help menu to the screen
exit 1 #force exit script
fi

printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
printf "${GRN}${bold}Downloads Folder Hash/Filename\n${normal}${NC}"
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"

for file in *; do #for each file in d/l folder
	#dig out md5sum of each file
	md5sum "$file"
	#sed used to make output csv friendly
done | sed 's/  /+,/' | awk -F"+" '{print $1, $2, $3}' | sed 's/ ,/,/g'

printf "${bold}${GRN}--------------------------------\n${NC}${normal}"
printf "${GRN}${bold}Most Recent File:\n${NC}"
#dig out md5 of most recent file
md5sum "$mostRecent"
printf "${bold}${GRN}--------------------------------\n${NC}${normal}"

#stores the value of the most recent d/l's md5 hash
VTHash=$(md5sum $(ls -t | head -n1) | awk '{print $1}')

printf "${GRN}${bold}VirusTotal Summary:\n${normal}${NC}"

#post the hash value to vt, and return the amount of hits
#note that only the hash of the file is posted, not the file itself
#preventing potential uploading of sensative client docs or info
#note that if this hash is not in vt's db, no results will be returned
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey=$VTAPIToken --form resource=$VTHash | awk -F 'positives\":' '{printf "\nVT Hits: " $2}' | awk -F ' ' '{print $1$2$3$6$7}' | sed 's|["}]||g' 

printf "${bold}${GRN}--------------------------------\n${NC}${normal}"

#ask if user wants a full VT report
read -n 1 -s -r -p "Press any key to generate full VirusTotal Report..."

printf "\n"
printf "${GRN}${bold}Full VirusTotal Report:\n${normal}${NC}"

#extract vendor and threat columns from vt
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey=$VTAPIToken --form resource=$VTHash | sed 's|\},|\}\n|g' | column -t -s "," | sed 's/detected//g' | sed 's/version//g' | sed 's/"//g' | sed 's/"//g' | sed 's/{//g' | sed 's/://g' | sed 's/true//g' | sed 's/false//g' | sed 's/result//g' | sed 's/}//g' | sed 's/scans//g' | sed 's/null/NoResult/g' | sed 's/update//g' | sed 's/v //g' | sed 's/-- //g' | sed 's/AB //g' | sed 's/- //g' | sed 's/a //g' | sed 's/variant //g' | sed 's/of //g' | sed 's/( //g' | sed 's/eff //g' | sed 's/ )//g' | sed 's/) //g' | sed 's/(high //g' | sed 's/confidence) //g' | sed 's/ confidence)//g' | sed 's/of //g' | sed 's/(ai //g' | sed 's/score= //g' | sed 's/(A //g' | sed 's/(CLOUD //g' | sed 's/(W //g' | sed 's/confidence //g' | sed 's/ Malicious PE/Malicious PE/g' | sed 's/ PE/PE/g' | sed 's/[[:digit:]]\+\.//g' | sed 's/[0-9]//g' | sed 's/- //g' | sed 's/-- //g' | sed 's/ -//g'  | sed 's/v //g' | sed 's/AB //g' | column -t -s " " #| awk -F '{print $1}' #| sed 's/"//g' | sed 's/{//g' | sed 's/ /|/g'| sed 's/://g' | sed 's/detected//g' | sed 's/,//g' | sed 's/version//g' | sed 's/true//g' | sed 's/false//g' | sed 's/}//g' 
#printf "\n"