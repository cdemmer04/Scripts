#!/bin/bash


version=$1

if [[ -z "$version" ]]; then
    echo "Usage: $0 <version>"
    echo "  version: 'oss' for Grafana OSS, 'enterprise' for Grafana Enterprise"
    exit 1
fi

sudo apt-get install -y apt-transport-https software-properties-common wget

sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null


echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list


# Updates the list of available packages
sudo apt-get update


if [[ "$version" == "oss" ]]; then
    # Installs the latest OSS release:
    sudo apt-get install -y grafana
else
    # Installs the latest Enterprise release:
    sudo apt-get install -y grafana-enterprise
fi