#!/bin/bash
# Creator: Chiel Demmer

# Uninstall conflicting packages
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; 
    do sudo apt-get remove $pkg; 
done

# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# Install latest version
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Input (lowercase) if installation needs to be tested
echo "Do you want to test the Docker installation? (Y/N) [Default: N]"
read input 
input=$(echo $input | tr '[:lower:]' '[:upper:]')

# Run testing container
if [[ $input = "Y" ]]
then
    echo "Testing Docker installation..."
    sudo docker run --name testcontainer hello-world > /dev/null 2>&1
    exit_code=$?
    if [[ ! $exit_code -eq 0  ]]
    then
        echo "Test of Docker installation failed! Error code: $exit_code"
    else
        echo "Test of Docker installation succesfully finished!"
        docker rm -f testcontainer > /dev/null 2>&1
    fi
else
    echo "Skipping Docker installation test"
fi

