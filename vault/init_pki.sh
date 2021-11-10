#!/bin/bash

# Script variables
vault=localhost

# Initialize vault
docker exec vault vault operator init > ./credentials

# Unsealt vault
cat credentials | grep "Unseal Key 1"| cut -d ":" -f2 | xargs
cat credentials | grep "Unseal Key 2"| cut -d ":" -f2 | xargs
cat credentials | grep "Unseal Key 3"| cut -d ":" -f2 | xargs




