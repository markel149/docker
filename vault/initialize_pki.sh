VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=$(cat credentials | grep "Root Token" | cut -d ":" -f2 | xargs)

curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --request POST \
   --data '{"type":"pki"}' \
   $VAULT_ADDR/v1/sys/mounts/pki

curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --request POST \
   --data '{"max_lease_ttl":"87600h"}' \
   $VAULT_ADDR/v1/sys/mounts/pki/tune

tee payload5.json <<EOF
{
  "common_name": "example.com",
  "ttl": "87600h"
}
EOF

curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --request POST \
   --data @payload5.json \
   $VAULT_ADDR/v1/pki/root/generate/internal \
   | jq -r ".data.certificate" > CA_cert.crt

tee payload-url.json <<EOF
{
  "issuing_certificates": "$VAULT_ADDR/v1/pki/ca",
  "crl_distribution_points": "$VAULT_ADDR/v1/pki/crl"
}
EOF

curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --request POST \
   --data @payload-url.json \
   $VAULT_ADDR/v1/pki/config/urls


tee payload-role.json <<EOF
{
  "allowed_domains": "example.com",
  "allow_subdomains": true,
  "max_ttl": "720h"
}
EOF

curl --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload-role.json \
    $VAULT_ADDR/v1/pki/roles/example-dot-com
