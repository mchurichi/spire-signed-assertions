#!/bin/bash

# Simple menu to SPIRE server main functions.
# Requirements: make, SPIRE repository in /spire. This script also needs to be at SPIRE directory.


start_spire_server () {
    # Start the SPIRE Server as a background process
    echo "Starting spire-server..."
    sleep 1
    sudo spire-server run -config /spire/conf/server/server.conf & 
    sleep 2
}

stop_spire() {
    sudo kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
    sudo kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
}

reset_spire() {
    sudo kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
    sudo kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
    sudo rm -rf /spire/.data
}

create_spiffeid() {
    echo "Enter the SPIFFE-ID:"
    read spiffeid
    echo "Enter the Parent-ID:"
    read parentid    
    echo "Enter the selector:"
    read selector

    echo $spiffeid
    echo $selector

    sudo spire-server entry create -parentID spiffe://example.org/$parentid -spiffeID spiffe://example.org/$spiffeid -selector $selector
}


oauth2spiffeid() {
    echo "Enter the OAuth Token:"
    read oauthtoken
    echo "Enter the selector:"
    read selector

    tokeninfo=$(curl \
                --request POST \
                --data "access_token=$oauthtoken" \
                https://www.googleapis.com/oauth2/v1/tokeninfo)

    
    read userid < <(echo $tokeninfo | jq -r '.user_id')
    read ttl < <(echo $tokeninfo | jq -r '.expires_in')

    sudo spire-server entry create -parentID spiffe://example.org/host -ttl $ttl -spiffeID spiffe://example.org/$userid -selector $selector
}

delete_spiffeid() {
    echo "Enter the Entry ID:"
    read entryid

    sudo spire-server entry delete -entryID $entryid
}

list_spiffeids() {
    sudo spire-server entry show
}

count_spiffeids() {
    sudo spire-server entry count
}

update_spiffeid() {
     
	list_spiffeids	

	echo "Enter the EntryID:"
	read entryid

	echo "Enter the Selector:"
	read selector

	echo "Enter the ParentID"
	read parentid

	echo "Enter the new SPIFFE-ID:"
	read spiffeid
	
	sudo spire-server entry update -entryID $entryid -selector $selector -parentID $parentid -spiffeID $spiffeid
	
 }

# mint_JWT() {

# }

# mint_x509() {

# }

list_agents() {
    sudo spire-server agent list
}

count_agents() {
    sudo spire-server agent count
}

generate_jointoken () {
# Generate a one time Join Token. 
# Use the -spiffeID option to associate the Join Token with spiffe://example.org/host SPIFFE ID. 
echo "Enter the SPIFFE-ID:"
read spiffeid

echo "Generating token..."
sleep 1
tmp=$(sudo spire-server token generate -spiffeID spiffe://example.org/$spiffeid)
echo $tmp
token=${tmp:7}
# echo $token >> tokens.lst
echo "Generated token: $token. \n Ready to start a new agent."
}

start_spire_agent () {

    generate_jointoken
    # Start the SPIRE Agent as a background process using the token passed by parameter.
    echo "Starting spire-agent..."
    sleep 1
    sudo spire-agent run -joinToken $token -config /spire/conf/agent/agent.conf &
    sleep 1
    token=''
}

check_spire_server () {
    sudo spire-server healthcheck
}

ban_agent() {
    echo "Enter the SPIFFE-ID:"
    read agentid

    sudo spire-server agent ban -spiffeID $agentid
}

evict_agent() {
    echo "Enter the SPIFFE-ID:"
    read spiffeid

    sudo spire-server agent evict -spiffeID $spiffeid
}

SPIFFEID2JWT() {

    # usage:
    # Bellow is a simple fixed example. Needs to be developed.
    # ./jwt_gen.sh <parent-id> <aat> <spiffe-id> <dpr>
    echo "Not implemented. :("
    
    
}

menu_server() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
+---------------------------------------------------------+
                  \033[1mSPIRE SERVER\033[0m
+---------------------------------------------------------+
 \033[1mServer status:\033[0m $status 
 \033[1mNumber of agents:\033[0m $agents 
 \033[1mNumber of registration entries:\033[0m $entries 
+---------------------------------------------------------+ 
 \033[1m1)\033[0m Server management
 \033[1m2)\033[0m Agents
 \033[1m3)\033[0m Registration Entries
 \033[1m0)\033[0m Back
+---------------------------------------------------------+
 Choose an option: " 
    read -r ans
    case $ans in
        1)
            menu_server_mgmt
            ;;
        2)
            menu_server_agents
            ;;
        3)
            menu_server_spiffeid
            ;;
        0)
            echo "Bye bye."
            exit 0
            ;;
        *)
            echo "Wrong option."
            ;;

    esac
}

menu_server_mgmt() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
+---------------------------------------------------------+
               \033[1mSPIRE SERVER MANAGEMENT\033[0m
+---------------------------------------------------------+
 \033[1mServer status:\033[0m $status 
 \033[1mNumber of agents:\033[0m $agents 
 \033[1mNumber of registration entries:\033[0m $entries 
+---------------------------------------------------------+ 
 \033[1m1)\033[0m Start
 \033[1m2)\033[0m Stop
 \033[1m3)\033[0m Stop and reset all
 \033[1m0)\033[0m Back
+---------------------------------------------------------+
Choose an option:  "
    read -r ans
    case $ans in
        1)
            start_spire_server
            read
            clear
            menu_server_mgmt
            ;;
        2)
            stop_spire
            read
            clear
            menu_server_mgmt
            ;;
        3)
            reset_spire
            read
            clear
            menu_server_mgmt
            ;;
        0)
            menu_server
            ;;
        *)
            echo "Wrong option."
            ;;
    esac
}

menu_server_agents() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
+---------------------------------------------------------+
                \033[1mSPIRE SERVER AGENTS\033[0m
+---------------------------------------------------------+
 \033[1mServer status:\033[0m $status 
 \033[1mNumber of agents:\033[0m $agents 
 \033[1mNumber of registration entries:\033[0m $entries 
+---------------------------------------------------------+ 
 \033[1m1)\033[0m Start new agent
 \033[1m2)\033[0m List agents
 \033[1m3)\033[0m Ban agent
 \033[1m4)\033[0m Evict agent
 \033[1m0)\033[0m Back
+---------------------------------------------------------+
Choose an option:  "
    read -r ans
    case $ans in
        1)
            start_spire_agent $token
            read
            clear
            menu_server_agents
            ;;
        2)
            list_agents
            read
            clear
            menu_server_agents
            ;;
        3)
            ban_agents
            read
            clear
            menu_server_agents
            ;;
        4)
            evict_agent
            read
            clear
            menu_server_agents
            ;;
        0)
            menu_server
            ;;
        *)  
            echo "Wrong option."
            ;;
    esac
}

menu_server_spiffeid() {
    status=$(check_spire_server)
    agents=$(count_agents)
    entries=$(count_spiffeids)
    clear
    echo -ne "
+---------------------------------------------------------+
                 \033[1mSPIRE SERVER ENTRIES\033[0m
+---------------------------------------------------------+
 \033[1mServer status:\033[0m $status 
 \033[1mNumber of agents:\033[0m $agents 
 \033[1mNumber of registration entries:\033[0m $entries 
+---------------------------------------------------------+ 
 \033[1m1)\033[0m Create SPIFFE-ID
 \033[1m2)\033[0m List SPIFFE-IDs
 \033[1m3)\033[0m Delete SPIFFE-ID
 \033[1m4)\033[0m Create OAuth2SPIFFE-ID
 \033[1m5)\033[0m Create SPIFFE-ID2JWT
 \033[1m0)\033[0m Back
 +---------------------------------------------------------+
Choose an option:  "
    read -r ans
    case $ans in
        1)
            create_spiffeid
            read
            clear
            menu_server_spiffeid
            ;;
        2)
            list_spiffeids
            read
            clear
            menu_server_spiffeid
            ;;
        3)
            delete_spiffeid
            read
            clear
            menu_server_spiffeid
            ;;
        4)
            oauth2spiffeid
            read
            clear
            menu_server_spiffeid
            ;;
        5)
            SPIFFEID2JWT
            read
            clear
            menu_server_spiffeid
            ;;
        0)
            menu_server
            ;;
        *)
            echo "Wrong option."
            ;;
    esac
}

menu_server
