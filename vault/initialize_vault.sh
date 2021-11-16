#!/bin/bash

# Script variables
vault=localhost

# Initialize vault
docker exec vault vault operator init > ./credentials

# Unsealt vault

key1=$(cat credentials | grep "Unseal Key 1"| cut -d ":" -f2 | xargs)
key2=$(cat credentials | grep "Unseal Key 2"| cut -d ":" -f2 | xargs)
key3=$(cat credentials | grep "Unseal Key 3"| cut -d ":" -f2 | xargs)

echo $key1


echo "{\"key\":\"$key1\"}" > payload1
echo "{\"key\":\"$key2\"}" > payload2
echo "{\"key\":\"$key3\"}" > payload3


curl -X PUT --data @payload1 http://$vault:8200/v1/sys/unseal 
curl -X PUT --data @payload2 http://$vault:8200/v1/sys/unseal
curl -X PUT --data @payload3 http://$vault:8200/v1/sys/unseal


