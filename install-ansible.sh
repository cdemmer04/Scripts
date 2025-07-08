#!/bin/bash
# Install right version of Ansible
sudo apt-add-repository ppa:ansible/ansible -y
sudo apt update
sudo apt install ansible -y

# Testing ansible
# Input (lowercase) if installation needs to be tested
echo "Do you want to test the Ansible installation? (Y/N) [Default: N]"
read input 
input=$(echo $input | tr '[:lower:]' '[:upper:]')

# Run testing container
if [[ $input = "Y" ]]
then
    echo "Testing Ansible installation..."
    ansible -m ping localhost > /dev/null 2>&1
    exit_code=$?
    if [[ ! $exit_code -eq 0  ]]
    then
        echo "Test of Ansible installation failed! Error code: $exit_code"
    else
        echo "Test of Ansible installation succesfully finished!"
    fi
else
    echo "Skipping Ansible installation test"
fi