#!/bin/bash
## Lamassu installer
git clone https://github.com/lamassuiot/lamassu-compose
cd lamassu-compose

echo "Installing jq"
sudo apt install -y jq
echo ""

echo "Providing enviroment variables for compose-builder/gen-self-signed-certs.sh"
export C=ES
export ST=Guipuzcoa
export L=Arrasate
export O=Lamassu IoT
echo "Type your domain"
read
export DOMAIN=${REPLY}
echo "Done"
echo ""
echo "Domain: $DOMAIN"

echo "Generating self signed certs"
./compose-builder/gen-self-signed-certs.sh
echo "Done"
echo ""

echo "Changing elastic certs format to PKCS8"
openssl pkcs8 -in lamassu/elastic_certs/elastic.key -topk8 -out lamassu/elastic_certs/elastic-pkcs8.key -nocrypt
echo "Done."
echo ""

sed -i 's/dev\.lamassu\.io/'$DOMAIN'/g' .env
sed -i 's/dev\.lamassu\.io/'$DOMAIN'/g' docker-compose.yml

docker-compose up -d keycloak

while [ "$(curl -I https://$DOMAIN:8443 -k | head -n 1 | awk '{print $2}')" != 200 ]
do
	echo "Waiting for keycloak to start..."
	sleep 3
done
echo ""

echo "Creating keycloak users... "
docker-compose exec keycloak /opt/jboss/keycloak/bin/add-user-keycloak.sh -r lamassu -u enroller -p enroller --roles admin
docker-compose exec keycloak /opt/jboss/keycloak/bin/add-user-keycloak.sh -r lamassu -u operator -p operator --roles operator
docker-compose exec keycloak /opt/jboss/keycloak/bin/jboss-cli.sh --connect command=:reload
echo ""

echo "Logging into keycloak"
docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user admin --password admin
export KC_DEV_MANAGER_CLIENT_UUID=$(docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh create clients -r lamassu -s clientId=device-manager -s 'redirectUris=["*"]' -s 'webOrigins=["*"]' -s 'clientAuthenticatorType=client-secret' -s 'serviceAccountsEnabled=true' -i)

echo "kc_manager_client: $KC_DEV_MANAGER_CLIENT_UUID"

export KC_KIBANA_CLIENT_UUID=$(docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh create clients -r lamassu -s clientId=kibana -s 'redirectUris=["*"]' -s 'webOrigins=["*"]' -s 'clientAuthenticatorType=client-secret' -i)

echo "kc_client:  $KC_KIBANA_CLIENT_UUID"
export KC_DEV_MANAGER_CLIENT_UUID=`echo $KC_DEV_MANAGER_CLIENT_UUID | sed 's/\\r//g'`

export KC_KIBANA_CLIENT_UUID=`echo $KC_KIBANA_CLIENT_UUID | sed 's/\\r//g'`

export KC_DEV_MANAGER_CLIENT_SECRET=$(docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh create -r lamassu clients/$KC_DEV_MANAGER_CLIENT_UUID/client-secret -o | jq -r .value)

export KC_KIBANA_CLIENT_SECRET=$(docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh create -r lamassu clients/$KC_KIBANA_CLIENT_UUID/client-secret -o | jq -r .value)

sed -i 's/KEYCLOAK_DEV_MANAGER_CLIENT_SECRET_TO_BE_REPLACED/'$KC_DEV_MANAGER_CLIENT_SECRET'/g' .env

CLIENT_SCOPE_ROLE_ID=$(docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh get client-scopes -r lamassu | jq '.[] | select(.name=="roles") | .id' -r | sed -Ez '$ s/\n+$//')

docker-compose exec keycloak /opt/jboss/keycloak/bin/kcadm.sh create client-scopes/$CLIENT_SCOPE_ROLE_ID/protocol-mappers/models -r lamassu -s name=roles -s protocol=openid-connect -s protocolMapper=oidc-usermodel-realm-role-mapper -s 'config."multivalued"=true' -s 'config."userinfo.token.claim"=true' -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' -s 'config."claim.name"=roles' -s 'config."jsonType.label"=String'

curl -k --location --request POST "https://$DOMAIN:8443/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' |jq -r .access_token | jq -R 'split(".") | .[1] | @base64d | fromjson'

ADMIN_DN=$(openssl x509 -subject -nameopt RFC2253 -noout -in lamassu/elastic_certs/elastic.crt | sed 's/subject=//g')
sed -i 's/ADMIN_DN_TO_REPLACE/'$ADMIN_DN'/g' elastic/elasticsearch.yml

docker-compose build elastic

ELASTIC_ADMIN_USERNAME=$(awk -F'=' '/^ELASTIC_ADMIN_USERNAME/ { print $2}' .env)
ELASTIC_ADMIN_PASSWORD_HASH=$(docker-compose run elastic /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh -p $(awk -F'=' '/^ELASTIC_ADMIN_PASSWORD/ { print $2}' .env) | tr -dc '[[:print:]]')

ELASTIC_FLUENTD_USERNAME=$(awk -F'=' '/^ELASTIC_FLUENTD_USERNAME/ { print $2}' .env)
ELASTIC_FLUENTD_PASSWORD_HASH=$(docker-compose run elastic /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh -p $(awk -F'=' '/^ELASTIC_FLUENTD_PASSWORD/ { print $2}' .env) | tr -dc '[[:print:]]')

ELASTIC_JAEGER_USERNAME=$(awk -F'=' '/^ELASTIC_JAEGER_USERNAME/ { print $2}' .env)
ELASTIC_JAEGER_PASSWORD_HASH=$(docker-compose run elastic /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh -p $(awk -F'=' '/^ELASTIC_JAEGER_PASSWORD/ { print $2}' .env) | tr -dc '[[:print:]]')

ELASTIC_KIBANA_USERNAME=$(awk -F'=' '/^ELASTIC_KIBANA_USERNAME/ { print $2}' .env)
ELASTIC_KIBANA_PASSWORD=$(awk -F'=' '/^ELASTIC_KIBANA_PASSWORD/ { print $2}' .env)
ELASTIC_KIBANA_PASSWORD_HASH=$(docker-compose run elastic /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh -p $(awk -F'=' '/^ELASTIC_KIBANA_PASSWORD/ { print $2}' .env) | tr -dc '[[:print:]]')

echo $ELASTIC_ADMIN_USERNAME
echo $ELASTIC_ADMIN_PASSWORD_HASH
echo $ELASTIC_FLUENTD_USERNAME
echo $ELASTIC_FLUENTD_PASSWORD_HASH
echo $ELASTIC_JAEGER_USERNAME
echo $ELASTIC_JAEGER_PASSWORD_HASH
echo $ELASTIC_KIBANA_USERNAME
echo $ELASTIC_KIBANA_PASSWORD_HASH

sed -i 's/ELASTIC_ADMIN_USERNAME_TO_REPLACE/'$ELASTIC_ADMIN_USERNAME'/g' elastic/elastic-internal-users.yml
sed -i 's~ELASTIC_ADMIN_PASSWORD_TO_REPLACE~'$ELASTIC_ADMIN_PASSWORD_HASH'~g' elastic/elastic-internal-users.yml
sed -i 's/ELASTIC_FLUENTD_USERNAME_TO_REPLACE/'$ELASTIC_FLUENTD_USERNAME'/g' elastic/elastic-internal-users.yml
sed -i 's~ELASTIC_FLUENTD_PASSWORD_TO_REPLACE~'$ELASTIC_FLUENTD_PASSWORD_HASH'~g' elastic/elastic-internal-users.yml
sed -i 's/ELASTIC_JAEGER_USERNAME_TO_REPLACE/'$ELASTIC_JAEGER_USERNAME'/g' elastic/elastic-internal-users.yml
sed -i 's~ELASTIC_JAEGER_PASSWORD_TO_REPLACE~'$ELASTIC_JAEGER_PASSWORD_HASH'~g' elastic/elastic-internal-users.yml
sed -i 's/ELASTIC_KIBANA_USERNAME_TO_REPLACE/'$ELASTIC_KIBANA_USERNAME'/g' elastic/elastic-internal-users.yml
sed -i 's~ELASTIC_KIBANA_PASSWORD_TO_REPLACE~'$ELASTIC_KIBANA_PASSWORD_HASH'~g' elastic/elastic-internal-users.yml

sed -i 's/dev\.lamassu\.io/'$DOMAIN'/g' elastic/elastic-security-config.yml
docker-compose up -d elastic

while [ "$(curl -k https://$DOMAIN:9200)" != "Authentication finally failed" ]
do
	echo "Waiting for elatic server to start..."
	sleep 3
done

docker-compose exec elastic /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -icl -nhnv -cacert /usr/share/elasticsearch/config/elastic.crt -cert /usr/share/elasticsearch/config/elastic.crt -key /usr/share/elasticsearch/config/elastic-pkcs8.key

ELASTIC_ADMIN_PASSWORD=$(awk -F'=' '/^ELASTIC_ADMIN_PASSWORD/ { print $2}' .env)
BASIC_AUTH=$(printf "%s" "$ELASTIC_ADMIN_USERNAME:$ELASTIC_ADMIN_PASSWORD" | base64 )

#while [ "$(curl -k --request GET https://$DOMAIN:9200) | head -n 1 | awk '{print $2}'" != 200 ]

while [ "$(curl -k https://$DOMAIN:9200)" != "Authentication finally failed" ]
do
	echo "Waiting for elatic server to initialize..."
	sleep 3
done

curl -k --location --request PUT "https://$DOMAIN:9200/_opendistro/_security/api/rolesmapping/all_access" \
--header "Authorization: Basic $BASIC_AUTH" \
--header 'Content-Type: application/json' \
--data-raw '{
  "backend_roles" : [ "admin" ],
  "hosts" : [ ],
  "users" : [ ]
}'

TOKEN=$(curl -k --location --request POST "https://$DOMAIN:8443/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' |jq -r .access_token)

curl -k --location --request GET "https://$DOMAIN:9200/_cat/indices?format=json" --header "Authorization: Bearer $TOKEN"

TOKEN=$(curl -k --location --request POST "https://$DOMAIN:8443/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=operator' --data-urlencode 'password=operator' |jq -r .access_token)

curl -k --location --request GET "https://$DOMAIN:9200/_cat/indices?format=json" --header "Authorization: Bearer $TOKEN"

sed -i 's/dev\.lamassu\.io/'$DOMAIN'/g' kibana.yml
sed -i 's/KIBANA_USERNAME_TO_REPLACE/'$ELASTIC_KIBANA_USERNAME'/g' kibana.yml
sed -i 's/KIBANA_PASSWORD_TO_REPLACE/'$ELASTIC_KIBANA_PASSWORD'/g' kibana.yml
sed -i 's/KIBANA_KEYCLOAK_CLIENT_ID_TO_REPLACE/'$KC_KIBANA_CLIENT_SECRET'/g' kibana.yml

docker-compose up -d kibana

docker-compose up -d vault



while [ "$(curl -k -I --request GET https://$DOMAIN:8200 | head -n 1 | awk '{print $2}')" != 307 ]
do
	echo "Waiting for vault server to initialize..."
	sleep 3
done

docker-compose exec vault vault operator init -key-shares=3 -key-threshold=2 -tls-skip-verify -format=json > vault-credentials.json

export VAULT_CA_FILE=$(pwd)/lamassu/vault_certs/vault.crt
export VAULT_TOKEN=$(cat vault-credentials.json | jq .root_token -r)
export VAULT_ADDR=https://$DOMAIN:8200

curl --request PUT "$VAULT_ADDR/v1/sys/unseal" -k --header 'Content-Type: application/json' --data-raw "{\"key\": \"$(cat vault-credentials.json | jq -r .unseal_keys_hex[0])\" }"

curl --request PUT "$VAULT_ADDR/v1/sys/unseal" -k --header 'Content-Type: application/json' --data-raw "{\"key\": \"$(cat vault-credentials.json | jq -r .unseal_keys_hex[1])\" }"

cd compose-builder
./ca-provision.sh

cat intermediate-DMS.crt > ../lamassu/device-manager_certs/dms-ca.crt
cat CA_cert.crt >> ../lamassu/device-manager_certs/dms-ca.crt

cd ..

export CA_VAULTROLEID=$(curl --cacert $VAULT_CA_FILE --header "X-Vault-Token: ${VAULT_TOKEN}" ${VAULT_ADDR}/v1/auth/approle/role/Enroller-CA-role/role-id | jq -r .data.role_id )
export CA_VAULTSECRETID=$(curl --cacert $VAULT_CA_FILE --header "X-Vault-Token: ${VAULT_TOKEN}" --request POST ${VAULT_ADDR}/v1/auth/approle/role/Enroller-CA-role/secret-id | jq -r .data.secret_id)
# Set RoleID and SecretID in .env file
sed -i 's/ROLE_ID_TO_BE_REPLACED/'$CA_VAULTROLEID'/g' .env
sed -i 's/SECRET_ID_TO_BE_REPLACED/'$CA_VAULTSECRETID'/g' .env

docker-compose up -d

export TOKEN=$(curl -k --location --request POST "https://$DOMAIN:8443/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=admin-cli' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' |jq -r .access_token)

export DMS_REGISTER_RESPONSE=$(curl -k --location --request POST "https://$DOMAIN:8085/v1/csrs/Lamassu-Default-DMS/form" --header "Authorization: Bearer ${TOKEN}" --header 'Content-Type: application/json' --data-raw "{\"url\":\"https://${DOMAIN}:5000\", \"common_name\": \"Lamassu-Default-DMS\",\"country\": \"\",\"key_bits\": 3072,\"key_type\": \"rsa\",\"locality\": \"\",\"organization\": \"\",\"organization_unit\": \"\",\"state\": \"\"}")

echo $DMS_REGISTER_RESPONSE | jq -r .priv_key | sed 's/\\n/\n/g' | sed -Ez '$ s/\n+$//' > lamassu-default-dms.key

export DMS_ID=$(echo $DMS_REGISTER_RESPONSE | jq -r .csr.id)

curl -k --location --request PUT "https://$DOMAIN:8085/v1/csrs/$DMS_ID" --header "Authorization: Bearer $TOKEN" --header 'Content-Type: application/json' --data-raw '{"status": "APPROVED"}'

cp lamassu/lamassu.crt lamassu-default-dms/device-manager.crt
cp lamassu/lamassu.crt lamassu-default-dms/https.crt
cp lamassu/lamassu.key lamassu-default-dms/https.key

cp lamassu-default-dms.crt lamassu-default-dms/enrolled-dms.crt
cp lamassu-default-dms.key lamassu-default-dms/enrolled-dms.key

cd lamassu-default-dms
sed -i 's/dev\.lamassu\.io/'$DOMAIN'/g' index.js
docker-compose up -d
sleep 20
curl -k --location --request GET "https://$DOMAIN:8089/v1/devices/<DEVICE_ID>/cert" --header "Authorization: Bearer $TOKEN"

cd ..
docker-compose down
docker-compose up -d

curl --request PUT "$VAULT_ADDR/v1/sys/unseal" -k --header 'Content-Type: application/json' --data-raw "{\"key\": \"$(cat vault-credentials.json | jq -r .unseal_keys_hex[0])\" }"

curl --request PUT "$VAULT_ADDR/v1/sys/unseal" -k --header 'Content-Type: application/json' --data-raw "{\"key\": \"$(cat vault-credentials.json | jq -r .unseal_keys_hex[1])\" }"
