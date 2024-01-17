#!/bin/bash

start_spire_server () {
    # Start the SPIRE Server as a background process
    echo "Starting spire-server..."
    sleep 1
    /opt/spire-signed-assertions/bin/spire-server run -config /opt/spire-signed-assertions/conf/server/server.conf & 
    sleep 2
}
start_spire_server


generate_jointoken () {
# Generate a one time Join Token. 
echo "Generating token..."
sleep 1
tmp=$( /opt/spire-signed-assertions/bin/spire-server token generate -spiffeID spiffe://example.org/host)
echo $tmp
token=${tmp:7}
# echo $token >> tokens.lst
echo -e "Generated token: $token.\nReady to start a new agent."
}

start_spire_agent () {
    generate_jointoken
    # Start the SPIRE Agent as a background process using the token passed by parameter.
    echo "Starting spire-agent..."
    sleep 1
    /opt/spire-signed-assertions/bin/spire-agent run -joinToken $token -config /opt/spire-signed-assertions/conf/agent/agent.conf &
    sleep 1
    token=''
}
start_spire_agent

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/asserting_wl \
    -selector docker:label:type:assertingwl

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/subject_wl \
    -selector docker:label:type:subjectwl

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/subject_mob \
    -selector docker:label:type:subjectmob

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/target_wl \
    -selector docker:label:type:targetwl

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier \
    -selector docker:label:type:middletier

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier2 \
    -selector docker:label:type:middletier2

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier3 \
    -selector docker:label:type:middletier3

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier4 \
    -selector docker:label:type:middletier4

/opt/spire-signed-assertions/bin/spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier5 \
    -selector docker:label:type:middletier5
