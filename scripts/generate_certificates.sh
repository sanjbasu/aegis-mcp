#!/bin/bash
# Generate certificates for mTLS

set -e

CERT_DIR="./certs"
mkdir -p $CERT_DIR

# Generate CA private key
openssl genrsa -out $CERT_DIR/ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key $CERT_DIR/ca-key.pem \
    -out $CERT_DIR/ca.pem \
    -subj "/C=US/ST=Colorado/L=Denver/O=MCP Security/CN=MCP CA"

echo "CA certificate generated successfully"

# Function to generate service certificate
generate_service_cert() {
    SERVICE_NAME=$1
    
    # Generate private key
    openssl genrsa -out $CERT_DIR/${SERVICE_NAME}-key.pem 2048
    
    # Generate CSR
    openssl req -new -key $CERT_DIR/${SERVICE_NAME}-key.pem \
        -out $CERT_DIR/${SERVICE_NAME}.csr \
        -subj "/C=US/ST=Colorado/L=Denver/O=MCP Security/CN=${SERVICE_NAME}"
    
    # Sign certificate
    openssl x509 -req -days 365 -in $CERT_DIR/${SERVICE_NAME}.csr \
        -CA $CERT_DIR/ca.pem -CAkey $CERT_DIR/ca-key.pem \
        -CAcreateserial -out $CERT_DIR/${SERVICE_NAME}.pem \
        -extensions v3_req -extfile <(
            cat <<EOF
[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.internal
DNS.3 = localhost
EOF
        )
    
    # Clean up CSR
    rm $CERT_DIR/${SERVICE_NAME}.csr
    
    echo "Certificate for ${SERVICE_NAME} generated successfully"
}

# Generate certificates for services
generate_service_cert "api_gateway"
generate_service_cert "user_service"
generate_service_cert "payment_service"

# Set appropriate permissions
chmod 600 $CERT_DIR/*-key.pem
chmod 644 $CERT_DIR/*.pem

echo "All certificates generated successfully!"
