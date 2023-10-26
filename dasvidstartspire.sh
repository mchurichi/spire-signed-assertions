#!/bin/bash

     sudo kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
     sudo kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
     sudo rm -rf /spire/.data

sudo spire-server run -config /spire/conf/server/server.conf &
sleep 3

tmp=$( sudo spire-server token generate -spiffeID spiffe://example.org/host)
echo $tmp
token=${tmp:7}
sudo spire-agent run -joinToken $token -config /spire/conf/agent/agent.conf &
sleep 3
sudo spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/asserting_wl \
    -selector docker:label:type:assertingwl