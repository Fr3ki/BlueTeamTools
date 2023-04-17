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
	echo "View in browser: https://www.abuseipdb.com/check/$IP"
}

#Define VirusTotal function
VT_Check () {
	HEADER="x-apikey: ${APIKEY}"
	SEARCH=$(curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$IP --header "${HEADER}")
	clear && echo "---Results for: $IP---"
	echo "{ $(echo $SEARCH | cut -d "," -f5,6,7,8,9) 
	} }" | jq | sed 's/[{}]*//g' 
	echo "View in browser: https://www.virustotal.com/gui/ip-address/$IP"

}

URL_Scan () { 

	SEARCH=$(curl -X POST "https://urlscan.io/api/v1/scan/" -H "Content-Type: application/json" -H "API-Key: $APIKEY" -d "{ \"url\": \"$IP\", \"visibility\": \"public\" }")

	UUID=$(echo $SEARCH | grep "uuid" | cut -d " " -f6 | sed 's/^"\(.*\)",\?$/\1/g')
	RESULT="$(curl https://urlscan.io/api/v1/result/$UUID/)"
	STATUS="$(echo $RESULT | cut -d " " -f13)"
	
	while [ "${STATUS}" == "404" ]
	do
		clear && echo "Scanning..."
		RESULT="$(curl https://urlscan.io/api/v1/result/$UUID/)"
		STATUS="$(echo $RESULT | cut -d " " -f13)"
		sleep 15s
	done

	clear && echo "---Results for: $IP---"
	echo -e "\nPage Details: "
	echo "$(echo $RESULT | jq .page | sed 's/[{}]*//g')"
	echo -e "\nEngine Verdicts: "
	echo "$(echo $RESULT | jq .verdicts.engines | sed 's/[{}]*//g')"

	URL="$(echo $RESULT | jq .task.reportURL)"

	echo -e "\nView in browser: $URL"


}

#Use the VirusTotal Tool
if [ "${SVC,,}" == "-v" ] || [ "${SVC,,}" == "--virustotal" ]; then
	
	#Run the VirusTotal check
	VT_Check

elif [ "${SVC,,}" == "-a" ] || [ "${SVC,,}" == "--abuseipdb" ]; then
		
	#Run the AbuseIPDB check
	ABIPDB_Check

elif [ "${SVC,,}" == "-u" ] || [ "${SVC,,}" == "--urlscan" ]; then 
	
	#Run the URL Scan	
	URL_Scan
	
#Help menu
elif [ "${SVC,,}" == "h" ] || [ "${SVC,,}" == "help" ] || [ "${SVC,,}" == "-h" ]; then
	echo "This is a tool for fast OSINT searches on URLs or IPs using the APIs of the tools listed below.

Usage: checkip [a/v/u]... [API key for the service]... [IP/URL to check]

-a/--abuseipdb	AbuseIPDB Search
-v/--virustotal	Virustotal Search
-u/--urlscan    URLScan Search

Author: Fr3ki [https://github.com/Fr3ki	| https://twitter.com/Fr3ki_]"

#If invalid/no usage is detected
else
	echo "Please specify a service [VirusTotal (V)/AbuseIPDB (A)/URLScan (U)] or -h for help"
fi
