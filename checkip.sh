#!/bin/bash

#Set the command line arguments as varriables
SVC="$1"
APIKEY=$2
IP=$3

#Define AbuseIPDB function
ABIPDB_Check () {
	SEARCH="$(curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$IP" -d maxAgeInDays=90 -d verbose -H "Key: $APIKEY" -H "Accept: application/json")"
	clear && echo "---Results for: $IP---"
	echo "{
	$(echo $SEARCH | cut -d "," -f4,5,9,12)
	}" | jq | sed 's/[{}]*//g'
}

#Define VirusTotal function
VT_Check () {
	HEADER="x-apikey: ${APIKEY}"
	SEARCH=$(curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$IP --header "${HEADER}")
	clear && echo "---Results for: $IP---"
	echo "{ $(echo $SEARCH | cut -d "," -f5,6,7,8,9) 
	} }" | jq | sed 's/[{}]*//g' 

}

#Use the VirusTotal Tool
if [ "${SVC,,}" == "-v" ] || [ "${SVC,,}" == "--virustotal" ]; then
	
	#Run the VirusTotal check
	VT_Check

elif [ "${SVC,,}" == "-a" ] || [ "${SVC,,}" == "--abuseipdb" ]; then
		
	#Run the AbuseIPDB check
	ABIPDB_Check

#Help menu
elif [ "${SVC,,}" == "h" ] || [ "${SVC,,}" == "help" ] || [ "${SVC,,}" == "-h" ]; then
	echo "This is a tool for fast OSINT searches on IPs using VirusTotal or AbuseIPDB

Usage: checkip [a/v]... [API key for the service]... [IP to check]

-a/--abuseipdb	AbuseIPDB Search
-v/--virustotal	Virustotal Search

Author: Fr3ki [https://github.com/Fr3ki	| https://twitter.com/Fr3ki_]"

#If invalid/no usage is detected
else
	echo "Please specify a service [VirusTotal (V)/AbuseIPDB (A)] or -h for help"
fi
