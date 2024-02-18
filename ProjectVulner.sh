#!/bin/bash

# Get current Epoch time
ET=$(date +%s)

# Create and set permissions for the project directory
sudo mkdir -p ProjectVulnerJBv6
sudo chmod a+rw ProjectVulnerJBv6
cd ProjectVulnerJBv6

# Set the current working directory
MAINFOLD=$(pwd)

# Get local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Define text formatting variables
bold=$(tput bold)
normal=$(tput sgr0)
U=$(tput smul)
N=$(tput rmul)

# Function to start the script and set the output directory
STARTDIR()
{
	echo "${U}Enter a name for the script output directory:${N}"
	read DIRNAME
	echo "Output directory - $DIRNAME "
	mkdir -p $DIRNAME
	chmod a+rw $DIRNAME
	cd $DIRNAME
	DIRNAME2=$(pwd)
	mkdir $ET
	cd $ET
	HOME=$(pwd)
	STARTINFO

}

# Function to display start information
STARTINFO()
{

	echo ""
	echo "Epoch time: ${bold}$ET"${normal}
	echo "[+] local ip address - ${bold}$LOCAL_IP"${normal}
	
	DEPENDENCIES
}

# Function to check and install required dependencies
DEPENDENCIES()
{
	
	# Check if nmap is installed
    if ! command -v nmap &> /dev/null; then
        missing_tools+=("nmap")
    fi

    # Check if masscan is installed
    if ! command -v masscan &> /dev/null; then
        missing_tools+=("masscan")
    fi
    
    # Check if masscan is installed
    if ! command -v hydra &> /dev/null; then
        missing_tools+=("hydra")
    fi
    
    # If any tools are missing, prompt the user to install them
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "[-] ${bold}The following tools are missing: ${missing_tools[@]} ${normal}"
        
        read -p "Do you want to install them? (y/n): " choice

        case "$choice" in
            [Yy])
                # Install the missing tools using apt-get
                sudo apt-get update
                sudo apt-get install "${missing_tools[@]}"
                ;;
            [Nn])
                echo "${bold}You chose not to install the missing tools. Exiting.${normal}"
                exit 1
                ;;
            *)
                echo "${bold}Invalid choice. Exiting.${normal}"
                exit 1
                ;;
        esac
    else
        echo "[+] ${bold}All required tools are installed. ${normal}"
        echo ""
    fi
    
    MENU
}

# Function to display the main menu
MENU()
{
exit=0

while [ $exit -ne 1 ]
do

	echo "${bold}Menu:${normal}"
	echo "------------------------------------------------------------------"
	echo ""
	echo "1 - Dependencies check"
	echo "2 - basic"
	echo "3 - full"
	echo ""
	
	read menuoption1;
	
	case $menuoption1 in 
	
		1)  echo ""
			echo "Dependencies check"
			echo ""
			
				DEPENDENCIES
			
		;;
		
		2)  echo ""
			echo "basic"
			echo ""
			
				SCANOPTION1
				MASSCAN
				HYDRALISTOPTIONBASIC
				
				 
				
		;;
	
		3)  echo ""
			echo "full"
			echo ""
			
				SCANOPTION1
				MASSCAN
				HYDRALISTOPTIONFULL
				
		;;
		
		*)  echo ""
			echo "Wrong input, aborting." && exit=1 
		
		;;
		
	esac
	
done

}


# Function to get target IP and start the scanning process
SCANOPTION1()
{


	echo "${bold}Enter target IP: ${normal}"
	echo ""
	read IP
	echo""
	NMAPUSER

}

# Function to perform nmap scanning
NMAPUSER()
{
	while [ $exit -ne 1 ]
	do
		echo "[+] Scanning in proccess."
		#echo "sudo nmap $IP -O -p- -oG $HOME/$IP.txt > /dev/null 2>&1"
		#echo "$IP"
		#echo "$HOME/$IP.txt"
		sudo nmap $IP -O -p- -oG $HOME/$IP.txt > /dev/null 2>&1
		NMAPUSERPID=$!
		wait $NMAPUSERPID
		echo -n "[+] $(cat $HOME/$IP.txt | grep Up | sed 's/(/ /g; s/)/ /g')"
		#echo -n "[+] "cat $HOME/$IP.txt | grep Up | sed 's/(/ /g; s/)/ /g'
		NMAPUSERPID=$!
		wait $NMAPUSERPID
			exit=1
	done
}

# Function to perform TCP and UDP enumeration using masscan
MASSCAN()
{
	echo ""
	echo "[+] ${bold}Enum TCP in proccess.${normal}"
	echo ""
	
	# Extracting Up IPs from the file and scanning TCP ports
	HOSTIPS=$(cat $HOME/$IP.txt | grep Up | sed 's/(/ /g; s/)/ /g' | awk '{ print $2 }')
		for ip in $HOSTIPS
		do
			echo ${bold}"[+] Scanning $IP"${normal}
			
			# Running masscan to enumerate TCP ports
			sudo masscan -p1-65535 $IP --rate=1000 -oG $HOME/tcp_$IP.txt > /dev/null 2>&1 &
				
			masscan_tcp_pid=$!
			wait $masscan_tcp_pid		
			echo "[+] ${bold}Enum TCP completed.${normal}"
		
			PORTSQUANTITY=$(cat $HOME/tcp_$IP.txt | grep -i open | wc -l)
			PORTS=$(cat $HOME/tcp_$IP.txt | sed 's/\// /g' | awk '{print $(7)}' | tail -n +3 | head -n -2| tr '\n' ',' | sed 's/,$/\n/')
		
				if (( $PORTSQUANTITY > 0 ))
				then 
					echo "[+] found ${bold}$PORTSQUANTITY${normal} open tcp ports for ${bold}$IP "${normal}
					echo "[+] Saved to ${bold}$HOME/tcp_$IP.txt"${normal}
					echo""
					echo "[+] ${bold}Enum TCP version detection in proccess.${normal}"
					sudo nmap -O -sV -p $PORTS $IP -oN $HOME/tcp_nmap_$IP.txt > /dev/null 2>&1 &
					NMAPTCPVPID=$!
					wait $NMAPTCPVPID
					echo "[+] ${bold}Enum TCP version detection completed.${normal}"
					echo "[+] ${bold}saved to $HOME/tcp_nmap_$IP.txt ${normal}"
					echo ""
						
				else
					echo "[-] found ${bold}$PORTSQUANTITY${normal} open tcp ports for ${bold}$IP "${normal}
	
				fi
			
			echo "[+] ${bold}Enum UDP in proccess.${normal}"
			sudo masscan -p U:1-65535 $IP --rate=1000 -oG $HOME/udp_$IP.txt > /dev/null 2>&1 &
			
			masscan_udp_pid=$!
			wait $masscan_udp_pid	
			echo "[+] ${bold}Enum UDP completed. ${normal}"
						
						 
			PORTSQUANTITYUDP=$(cat $HOME/udp_$IP.txt | grep -i open | wc -l)
			PORTSUDP=$(cat $HOME/udp_$IP.txt | sed 's/\// /g' | awk '{print $(7)}' | tail -n +3 | head -n -2  | tr '\n' ',' | sed 's/,$/\n/')
				if (( $PORTSQUANTITY > 0 ))
				then 
					echo "[+] found ${bold}$PORTSQUANTITYUDP${normal} open udp ports for ${bold}$IP "${normal}
					echo "[+] Saved to ${bold}$HOME/udp_$IP.txt"${normal}
					echo""
					
					echo "[+] ${bold}Enum UDP version detection in proccess. ${normal}"
					sudo nmap -sV -sU -p $PORTSUDP $IP -oN $HOME/udp_nmap_$IP.txt > /dev/null 2>&1 &
					NMAPUDPVPID=$!
					wait $NMAPUDPVPID
					echo "[+] ${bold}Enum UDP version detection completed. ${normal}"
					echo "[+] Saved to ${bold}$HOME/udp_nmap_$IP.txt ${normal}"

					
					else
					echo "[-] found ${bold}$PORTS${normal} open udp ports for ${bold}$IP "${normal}
					
				fi
			
		echo ""
		done
}


HYDRALISTOPTIONBASIC()
{
	exit=0

	while [ $exit -ne 1 ]
	do

		echo "${bold}Hydra password list options:${normal}"
		echo "------------------------------------------------------------------"
		echo ""
		echo "1 - Supply your own list"
		echo "2 - Use script supplied list "
		echo ""
	
		read menuoption2;
	
		case $menuoption2 in 
	
		1)  echo ""
			echo "${bold}Enter full path to password list: ${normal}"
				read "SSHPASS" "FTPPASS" "RDPPASS" "TNPASS"
				
				echo "SSHPASS $SSHPASS"
				echo "RDPPASS $RDPPASS"
				echo "TNPASS $TNPASS"
				echo "FTPPASS $FTPPASS"
				HYDRA
				SCRIPTRESULTS
				SEARCH
				ZIP
			echo ""
	
		;;
	
		2)  echo ""
			echo "${bold}Using script supplied password list. ${normal}"
			echo ""
				HYDRASSH
				SCRIPTRESULTS
				SEARCH
				ZIP
				exit

		;;
		
		*)  echo ""
			echo "${bold}Wrong input, aborting.${normal}" && exit=1 
		
		;;
		
		esac
	
	done
}

# Function to display password list menu 
HYDRALISTOPTIONFULL()
{
	exit=0

	while [ $exit -ne 1 ]
	do

		echo "${bold}Hydra password list options:${normal}"
		echo "------------------------------------------------------------------"
		echo ""
		echo "1 - Supply your own list"
		echo "2 - Use script supplied list "
		echo ""
	
		read menuoption2;
	
			case $menuoption2 in 
	
				1)  echo ""
					echo "${bold}Enter full path to password list:${normal}"
					read "SSHPASS" "FTPPASS" "RDPPASS" "TNPASS"
				
					echo "SSHPASS $SSHPASS"
					echo "RDPPASS $RDPPASS"
					echo "TNPASS $TNPASS"
					echo "FTPPASS $FTPPASS"
					HYDRA
					echo ""
	
				;;
	
				2)  echo ""
					echo "${bold}using script supplied password list.${normal}"
					echo ""
					HYDRASSH
					VULN
					SCRIPTRESULTS
					SEARCH
					ZIP
					exit

				;;
		
				*)  echo ""
					echo "${bold}Wrong input, aborting.${normal}" && exit=1 
		
				;;
		
		esac
	
	done
}

# Function to download and split user and password list
HYDRASSH()
{
	mkdir -p $MAINFOLD/HydraLists
	chmod a+rw $MAINFOLD/HydraLists

	
	max_retries=3
	retry_count=0

	while [ $retry_count -lt $max_retries ]; do
		if wget -P $MAINFOLD/HydraLists https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt > /dev/null 2>&1; then
			PID=$!
			wait $PID
			echo "[+] ${bold}Downloaded ssh-betterdefaultpasslist.txt to $MAINFOLD/HydraLists ${normal}"
			echo "[+] ${bold}Splitting to user and password list ${normal}"
        
			# Extract usernames and passwords and store them in separate files
			cat $MAINFOLD/HydraLists/ssh-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $1}' > $MAINFOLD/HydraLists/sshuserlist.txt
			cat $MAINFOLD/HydraLists/ssh-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $2}' > $MAINFOLD/HydraLists/sshpasslist.txt
        
			# Set variables pointing to the extracted username and password files
			SSHUSER=$MAINFOLD/HydraLists/sshuserlist.txt
			SSHPASS=$MAINFOLD/HydraLists/sshpasslist.txt
			
			# Reset retry count
			retry_count=0
        
			# Break out of the loop if successful
			break
		else
			((retry_count++))
			echo "[-] ${bold}Error: Unable to download ssh-betterdefaultpasslist.txt. Retrying... (Attempt $retry_count)${normal}"
		fi
	done

	# Check if max retries reached
	if [ $retry_count -eq $max_retries ]; then
		echo "[-] ${bold}Error: Maximum number of retries reached. Exiting.${normal}"
		exit 1
	fi
		

HYDRAFTP
	
}

# Function to download and split user and password list
HYDRAFTP()
{
	max_retries=3
	retry_count=0

	while [ $retry_count -lt $max_retries ]; do
		if wget -P $MAINFOLD/HydraLists https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt > /dev/null 2>&1; then
			PID=$!
			wait $PID
			echo "[+] ${bold}Downloaded ftp-betterdefaultpasslist.txt to $MAINFOLD/HydraLists ${normal}"
			echo "[+] ${bold}Splitting to user and password list ${normal}"
        
			# Extract usernames and passwords and store them in separate files
			cat $MAINFOLD/HydraLists/ftp-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $1}' > $MAINFOLD/HydraLists/ftpuserlist.txt
			cat $MAINFOLD/HydraLists/ftp-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $2}' > $MAINFOLD/HydraLists/ftppasslist.txt 
        
			# Set variables pointing to the extracted username and password files
			FTPUSER=$MAINFOLD/HydraLists/ftpuserlist.txt
			FTPPASS=$MAINFOLD/HydraLists/ftppasslist.txt
			
			# Reset retry count
			retry_count=0
        
			# Break out of the loop if successful
			break
		else
			((retry_count++))
			echo "[-] ${bold}Error: Unable to download ftp-betterdefaultpasslist.txt. Retrying... (Attempt $retry_count) ${normal}"
		fi
	done

	# Check if max retries reached
	if [ $retry_count -eq $max_retries ]; then
		echo "[-] ${bold}Error: Maximum number of retries reached. Exiting. ${normal}"
		exit 1
	fi
	HYDRATN
}

# Function to download and split user and password list
HYDRATN()
{
	max_retries=3
	retry_count=0

	while [ $retry_count -lt $max_retries ]; do
		if wget -P $MAINFOLD/HydraLists https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt > /dev/null 2>&1; then
			PID=$!
			wait $PID
			echo "[+] ${bold}Downloaded telnet-betterdefaultpasslist.txt to $MAINFOLD/HydraLists ${normal}"
			echo "[+] ${bold}Splitting to user and password list ${normal}"
        
			# Extract usernames and passwords and store them in separate files
			cat $MAINFOLD/HydraLists/telnet-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $1}' > $MAINFOLD/HydraLists/tnuserlist.txt
			cat $MAINFOLD/HydraLists/telnet-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $2}' > $MAINFOLD/HydraLists/tnpasslist.txt
        
			# Set variables pointing to the extracted username and password files
			TNUSER=$MAINFOLD/HydraLists/tnuserlist.txt
			TNPASS=$MAINFOLD/HydraLists/tnpasslist.txt
			
			# Reset retry count
			retry_count=0
        
			# Break out of the loop if successful
			break
		else
			((retry_count++))
			echo "[-] ${bold}Error: Unable to download telnet-betterdefaultpasslist.txt. Retrying... (Attempt $retry_count) ${normal}"
		fi
	done

	# Check if max retries reached
	if [ $retry_count -eq $max_retries ]; then
		echo "${bold}Error: Maximum number of retries reached. Exiting. ${normal}"
		exit 1
	fi
	
	HYDRA
}

# Function to brute force ssh/ftp/rdp/telnet and to find weak credentials
HYDRA()
{
    
		for SERVICE in ftp ssh telnet rdp; do
        result=$(cat $HOME/tcp_nmap_$IP.txt | sed 's/\// /g' | awk '{print $4}' | head -n -11 | tail -n +6 | grep -i $SERVICE)

        if [ -n "$result" ]; then
            PORTS=$(cat $HOME/tcp_nmap_$IP.txt | sed 's/\// /g' | awk '{print $1, $4}' | head -n -11 | tail -n +6 | grep -i $SERVICE | awk '{print $1}')

        if [ -n "$PORTS" ]; then
			echo ""


        # Loop through each port for the service
        while read -r PORT; do
			echo "[+] Found ${bold} $SERVICE ${normal} on port ${bold} $PORT ${normal}"

 
			case "$SERVICE" in
			
				"ftp")
                      
						echo "${bold}Testing weak usernames and passwords on $IP $PORT $SERVICE ${normal}"
                        
                        #Remove "timeout -k 5m 5m" for disabling timeout.
                        timeout -k 5m 5m sudo hydra -L $FTPUSER -P $FTPPASS -f -s $PORT -o $HOME/Hydra_${SERVICE}_${PORT}.txt $IP $SERVICE > /dev/null 2>&1 &
                        FTPHYDRAPID=$!
                        wait $FTPHYDRAPID
                        
							if grep -q "login" "$HOME/Hydra_${SERVICE}_${PORT}.txt"; then
								LOGIN=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $5}' )
								PASSWORD=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $7}' )
								echo "[+] Found login ${bold}$LOGIN ${normal} and password ${bold}$PASSWORD ${normal}"
							

							else
								echo "[-] ${bold}Login and password not found. ${normal}"
							fi

                       
					;;
				"ssh")
                      echo "${bold}Testing weak usernames and passwords on $IP $PORT $SERVICE ${normal}"
                      #Remove "timeout -k 5m 5m" for disabling timeout.
                      timeout -k 5m 5m sudo hydra -L $SSHUSER -P $SSHPASS -f -s $PORT -o $HOME/Hydra_${SERVICE}_${PORT}.txt $IP $SERVICE > /dev/null 2>&1 &
                      SSHHYDRAPID=$!
                      wait $SSHHYDRAPID
                         
							if grep -q "login" "$HOME/Hydra_${SERVICE}_${PORT}.txt"; then
								LOGIN=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $5}' )
								PASSWORD=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $7}' )
								echo "[+] Found login ${bold}$LOGIN ${normal} and password ${bold}$PASSWORD ${normal}"
							else
								echo "[-] ${bold}Login and password not found. ${normal}"
							fi
             
                    ;;
			"telnet")
					echo "${bold}Testing weak usernames and passwords on $IP $PORT $SERVICE ${normal}"
					#Remove "timeout -k 5m 5m" for disabling timeout.
					timeout -k 5m 5m sudo hydra -L $TNUSER -P $TNPASS -f -s $PORT -o $HOME/Hydra_${SERVICE}_${PORT}.txt $IP $SERVICE > /dev/null 2>&1 &
					TELNETHYDRAPID=$!
					wait $TELNETHYDRAPID
                         
							if grep -q "login" "$HOME/Hydra_${SERVICE}_${PORT}.txt"; then
								LOGIN=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $5}' )
								PASSWORD=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $7}' )
								echo "[+] Found login ${bold}$LOGIN ${normal} and password ${bold}$PASSWORD ${normal}"
							else
								echo "[-] ${bold}Login and password not found. ${normal}"
							fi
                    
					;;
				"rdp")
					echo "${bold}Testing weak usernames and passwords on $IP $PORT $SERVICE ${normal}"
					#Remove "timeout -k 5m 5m" for disabling timeout.
                    timeout -k 5m 5m sudo hydra -L $FTPUSER -P $FTPPASS -f -s $PORT -o $HOME/Hydra_${SERVICE}_${PORT}.txt $IP $SERVICE > /dev/null 2>&1 &
                    RDPHYDRAPID=$!
                    wait $RDPHYDRAPID
                         
							if grep -q "login" "$HOME/Hydra_${SERVICE}_${PORT}.txt"; then
								LOGIN=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $5}' )
								PASSWORD=$(cat $HOME/Hydra_${SERVICE}_${PORT}.txt | tail -n +2 | awk '{print $7}' )
								echo "[+] Found login ${bold}$LOGIN ${normal} and password ${bold}$PASSWORD ${normal}"
							else
								echo "[-] ${bold}Login and password not found. ${normal}"
							fi
                     
                            ;;
                    esac
                done <<< "$PORTS"
            else
                echo "[-] ${bold}No port found for $SERVICE. ${normal}"
            fi
        else
            echo "[-] ${bold}$SERVICE not found in the scan result. ${normal}"
        fi
    done

	


}

# Function to find vulnerabilities
VULN() 
{
     echo ""
    echo "[+] ${bold}Looking for vulnerabilities... ${normal}"
    echo ""

    sudo nmap "$IP" --script=vulners.nse -sV -oN "Vulns_$IP.txt" > /dev/null 2>&1 &
    NMAPVULN=$!
    wait $NMAPVULN

    if grep -q CVE "$HOME/Vulns_$IP.txt"; then
        echo "[+] ${bold}Vulnerabilities were found for $IP.${normal}"
        echo "[+] ${bold}Saved to Vulns_$IP.txt${normal}"
        echo ""
        
        
		# Menu for Choosing how to open vulnerabilities txt file
        echo "Choose an editor to open the Vulns_$IP.txt file:"
        echo "--------------------------------------------------"
        echo "  1. Geany"
        echo "  2. Nano"
        echo "  3. Current Terminal"
        echo "  4. No"
        echo ""

        read -p "Enter the number of your choice: " choice
        case "$choice" in
            1)
                geany "Vulns_$IP.txt"
                ;;
            2)
                nano "Vulns_$IP.txt"
                ;;
            3)
                # Open in the current terminal
                cat Vulns_$IP.txt | head -n -3 | tail -n +5
                ;;
            4)
                echo "[-] File not opened. Continuing..."
                ;;
            *)
                echo "[-] Invalid choice. File not opened. Continuing..."
                ;;
        esac

    else
        echo "[-] No vulnerabilities were found for ${bold}$IP.${normal}"
        echo ""
    fi
}

# Function to print the script results.
SCRIPTRESULTS()
{
	echo "${bold}Script results: ${normal}"
	
	
	 for FILE1 in $HOME/tcp_nmap_*; do
        if grep -q "open" "$FILE1"; then
            FILE1NAME=$(basename "$FILE1" | sed 's/tcp_nmap_//' | sed 's/.txt//')
            FILE1NAMEI=$(basename "$FILE1")
            echo ""
            echo "$FILE1NAMEI"
            echo "------------------------"
            echo "$FILE1NAME"
            echo ""
            cat "$FILE1" | sed 's/\// /g' | awk '{ print $1, $2, $3, $4, $5 }' | grep -i open
            echo ""
            cat "$FILE1" | grep -i running
            cat "$FILE1" | grep -i MAC
            cat "$FILE1" | grep -i "OS details"
            echo ""
        fi
    done

    echo "===================================================="

    for FILE2 in $HOME/udp_nmap_*; do
        if grep -q "open" "$FILE2"; then
            FILE2NAME=$(basename "$FILE2" | sed 's/udp_nmap_//' | sed 's/.txt//')
            FILE2NAMEI=$(basename "$FILE2")
            echo ""
            echo "$FILE2NAMEI"
            echo "------------------------"
            echo "$FILE2NAME"
            echo ""
            cat "$FILE2" | sed 's/\// /g' | awk '{ print $1, $2, $3, $4, $5 }' | grep -i open
            echo ""
            cat "$FILE2" | grep -i running
            cat "$FILE2" | grep -i MAC
            cat "$FILE2" | grep -i "OS details"
            echo ""
        fi
    done

    echo "===================================================="

    for FILE3 in $HOME/Hydra_*; do
        if grep -q "login" "$FILE3"; then
            FILE3NAME=$(basename "$FILE3" | sed 's/Hydra_//' | sed 's/.txt//')
            FILE3NAMEI=$(basename "$FILE3")
            echo ""
            echo "$FILE3NAMEI"
            echo "------------------------"
            echo "$FILE3NAME"
            echo ""
            echo -n "[+] $(cat "$FILE3" | grep -i login | sed 's/\[\|\]/ /g')"
            echo ""
        fi
    done
	
}

# Function to search through the files.
SEARCH() 
{

	 while true; do
        # Ask the user if they want to search in files
        read -p "Would you like to search in files? [y/n]: " SEARCH_FILE_CHOICE
        case "$SEARCH_FILE_CHOICE" in
            [yY])
            
                # Prompt the user for a word to search
                read -p "Enter a word to search for: " SEARCH_WORD

                echo ""
                echo "[+] Searching for '$SEARCH_WORD' in files under $HOME directory:"
                echo ""

                # Loop through files in the $HOME directory
                for FILE in $HOME/*; do
                    if [ -f "$FILE" ]; then
                        # Search for the word in the file
                        RESULT=$(grep -nI "$SEARCH_WORD" "$FILE")
                        
                        # If the word is found, print the file name and results
                        if [ -n "$RESULT" ]; then
                            echo "[+] File: $FILE"
                            echo ""
                            echo "$RESULT"
                            echo "-------------------------"
                        fi
                    fi
                done

                ;;
            [nN])
                echo "[-] Continuing with the rest of the script."
                break
                ;;
            *)
                echo "[-] Invalid choice. Please enter 'y' or 'n'."
                ;;
        esac

        echo ""
        echo "[+] Search completed."
        echo ""
    done


}

# Function to zip the logs
ZIP()
{
	echo "${bold} Would you like to zip all the logs and results? [y/n] ${normal}"
	
	read -r ANSWER
	
	 case "$ANSWER" in
        [yY])
            # Check if the folder exists
            if [ -d "$MAINFOLD/$DIRNAME" ]; then
                # Zip logs and results
                zip -jr "$MAINFOLD/$DIRNAME/${ET}_logs_and_results.zip" "$MAINFOLD/$DIRNAME" > /dev/null 2>&1 &
                echo "zip -jr $MAINFOLD/$DIRNAME/$ET_logs_and_results.zip $MAINFOLD/$DIRNAME > /dev/null 2>&1 &"
                ZIPPID=$!
                wait $ZIPPID
                
                echo "[+] Logs and results have been zipped successfully to ${ET}_logs_and_results.zip "
            else
                echo "[-] Error: The specified folder $MAINFOLD/$DIRNAME does not exist. "
            fi
            ;;
        [nN])
            echo "[+] Skipping zip process."
            ;;
        *)
            echo "[-] Invalid input. Please enter 'y' or 'n'."
            ;;
    esac
}

 STARTDIR
