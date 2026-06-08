#!/bin/bash
# Disclaimer:
#   The sample scripts are not supported under any Microsoft standard support
#   program or service. The sample scripts are provided AS IS without warranty
#   of any kind. Microsoft further disclaims all implied warranties including,
#   without limitation, any implied warranties of merchantability or of fitness
#   for a particular purpose. The entire risk arising out of the use or
#   performance of the sample scripts and documentation remains with you.
#
# Synopsis:
#   Validates Azure IMDS attestation certificate chain on Linux VMs.
#
# Description:
#   This script performs the following checks:
#   Phase 1 - Verifies the IMDS endpoint (169.254.169.254) is reachable
#   Phase 2 - Fetches the attested document and extracts the signing certificate
#   Phase 3 - Validates the certificate chain against the system trust store
#   Phase 4 - Detects which OCSP intermediate the VM is using
#   Phase 5 - Checks the trust store for known IMDS certificates
#   Phase 6 - Tests connectivity to AIA, CRL, and OCSP endpoints
#   Phase 7 - Detects the distribution and shows the correct fix commands
#
# Notes:
#   Requires root/sudo privileges.
#   Requires openssl and python3.
#   Tested on Ubuntu 22.04, RHEL 9, SUSE 15.
#   Reference: https://aka.ms/AzVmIMDSValidation

set -euo pipefail

# ---- IMDS retry helper ------------------------------------------------------
# IMDS returns HTTP 410 Gone during legitimate maintenance / cert-rotation
# windows. Honor Retry-After if present; otherwise wait the documented
# transient-recovery window. One retry is enough — repeated 410s mean a
# longer outage that needs human follow-up, not more polling.
# CALIBRATION: expert-judgment - 70s default chosen as the documented IMDS
# transient-error recovery window; not measured against a real 410 distribution.
IMDS_RETRY_AFTER_DEFAULT=70

imds_curl_with_retry() {
    # $1=url, $2=output-file ("-" for stdout)
    local url="$1"
    local outfile="${2:--}"
    local hdrfile body code wait_secs retry_after
    hdrfile=$(mktemp)

    body=$(curl -s -D "$hdrfile" -w '\n%{http_code}' -H "Metadata:true" \
        --connect-timeout 5 "$url" 2>/dev/null) || { rm -f "$hdrfile"; return 1; }
    code="${body##*$'\n'}"
    body="${body%$'\n'*}"

    if [ "$code" = "410" ]; then
        retry_after=$(grep -i '^Retry-After:' "$hdrfile" | awk -F': ' '{print $2}' | tr -d '\r')
        wait_secs="$IMDS_RETRY_AFTER_DEFAULT"
        if [[ "$retry_after" =~ ^[0-9]+$ ]] && [ "$retry_after" -gt 0 ] && [ "$retry_after" -lt 600 ]; then
            wait_secs="$retry_after"
        fi
        echo "  [WARN] IMDS returned HTTP 410 Gone (transient - rotation/maintenance window)." >&2
        echo "         Waiting ${wait_secs}s, then retrying once..." >&2
        sleep "$wait_secs"
        body=$(curl -s -w '\n%{http_code}' -H "Metadata:true" --connect-timeout 5 "$url" 2>/dev/null) || { rm -f "$hdrfile"; return 1; }
        code="${body##*$'\n'}"
        body="${body%$'\n'*}"
    fi
    rm -f "$hdrfile"

    if [ "$code" != "200" ]; then
        return 1
    fi
    if [ "$outfile" = "-" ]; then
        printf '%s' "$body"
    else
        printf '%s' "$body" > "$outfile"
    fi
    return 0
}

echo "====================================================="
echo " Azure IMDS Attestation Certificate Chain Validator"
echo " Reference: https://aka.ms/AzVmIMDSValidation"
echo "====================================================="

# ---- Phase 1: IMDS Reachability ----
echo ""
echo "[Phase 1] IMDS Endpoint Reachability"
echo "-------------------------------------"
if imds_curl_with_retry "http://169.254.169.254/metadata/instance?api-version=2021-02-01" /dev/null; then
    echo "  [PASS] 169.254.169.254 is reachable"
else
    echo "  [FAIL] 169.254.169.254 is NOT reachable"
    echo "  Action: Check firewall rules and network configuration."
    echo "  Note: IMDS uses a link-local address handled by the hypervisor."
    echo "        Guest OS route changes cannot block IMDS; only firewall rules can."
    exit 1
fi

# ---- Phase 2: Attestation Fetch ----
echo ""
echo "[Phase 2] IMDS Attested Document"
echo "--------------------------------"
if ! ATTESTED_JSON=$(imds_curl_with_retry "http://169.254.169.254/metadata/attested/document?api-version=2018-10-01"); then
    echo "  [FAIL] Cannot retrieve attested document"
    exit 1
fi
if [ -z "$ATTESTED_JSON" ]; then
    echo "  [FAIL] Cannot retrieve attested document"
    exit 1
fi

python3 -c "
import json, sys, base64
doc = json.loads(sys.argv[1])
sig = base64.b64decode(doc['signature'])
with open('/tmp/imds_sig.der', 'wb') as f:
    f.write(sig)
print('  [PASS] Attested document retrieved ({} bytes signature)'.format(len(sig)))
" "$ATTESTED_JSON"

# Extract cert from PKCS#7 envelope
openssl pkcs7 -in /tmp/imds_sig.der -inform DER -print_certs -out /tmp/imds_cert.pem 2>/dev/null

LEAF_SUBJECT=$(openssl x509 -in /tmp/imds_cert.pem -noout -subject 2>/dev/null)
LEAF_ISSUER=$(openssl x509 -in /tmp/imds_cert.pem -noout -issuer 2>/dev/null)
LEAF_DATES=$(openssl x509 -in /tmp/imds_cert.pem -noout -dates 2>/dev/null)

echo "  Leaf: $LEAF_SUBJECT"
echo "  Issuer: $LEAF_ISSUER"
echo "  $LEAF_DATES"

# ---- Phase 3: Chain Validation ----
echo ""
echo "[Phase 3] Certificate Chain Validation"
echo "--------------------------------------"
VERIFY_RESULT=$(openssl verify /tmp/imds_cert.pem 2>&1)
if echo "$VERIFY_RESULT" | grep -q ": OK"; then
    echo "  [PASS] Certificate chain validates successfully"
    CHAIN_OK=true
else
    echo "  [FAIL] Certificate chain validation failed"
    echo "  $VERIFY_RESULT"
    CHAIN_OK=false
fi

# ---- Phase 3b: Pre-expiry Window Check ----
# openssl verify only fails AFTER a cert expires. OCSP intermediates rotate on
# a ~1-2 year cadence; warn 60 days ahead so ops moves to the new intermediate
# (Phase 4 detects which OCSP # is active) before silent failure.
# CALIBRATION: expert-judgment - 60 days chosen as standard ops lead time for
# certificate-rotation planning; not measured against IMDS rotation telemetry.
PRE_EXPIRY_WARNING_DAYS=60
echo ""
echo "[Phase 3b] Pre-expiry Window Check (${PRE_EXPIRY_WARNING_DAYS} days)"
echo "-------------------------------------"
EXPIRY_WARNINGS=0
NOW_EPOCH=$(date -u +%s)
# /tmp/imds_cert.pem contains the leaf + intermediates from the PKCS#7 envelope
csplit -z -s -b '%02d.pem' -f /tmp/imds_chain_ /tmp/imds_cert.pem '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null || true
for chain_pem in /tmp/imds_chain_*.pem; do
    [ -s "$chain_pem" ] || continue
    NOT_AFTER=$(openssl x509 -in "$chain_pem" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    SUBJECT=$(openssl x509 -in "$chain_pem" -noout -subject 2>/dev/null | sed 's/subject= *//')
    [ -z "$NOT_AFTER" ] && continue
    NOT_AFTER_EPOCH=$(date -u -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
    [ "$NOT_AFTER_EPOCH" = "0" ] && continue
    DAYS_REMAINING=$(( (NOT_AFTER_EPOCH - NOW_EPOCH) / 86400 ))
    if [ "$DAYS_REMAINING" -lt "$PRE_EXPIRY_WARNING_DAYS" ] && [ "$DAYS_REMAINING" -ge 0 ]; then
        echo "  [WARN] $SUBJECT"
        echo "         NotAfter (UTC): $NOT_AFTER"
        echo "         Days remaining: $DAYS_REMAINING"
        EXPIRY_WARNINGS=$((EXPIRY_WARNINGS + 1))
    fi
done
rm -f /tmp/imds_chain_*.pem
if [ "$EXPIRY_WARNINGS" -gt 0 ]; then
    echo "  Action: confirm a successor intermediate is published and pre-install it."
    echo "  Reference: https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details"
else
    echo "  [OK]   No chain certificates expire within ${PRE_EXPIRY_WARNING_DAYS} days."
fi

# ---- Phase 4: OCSP Detection ----
echo ""
echo "[Phase 4] OCSP Intermediate Detection"
echo "--------------------------------------"
OCSP_NUM=$(echo "$LEAF_ISSUER" | grep -oP 'OCSP \K[0-9]+' || echo "unknown")
echo "  Your VM uses OCSP intermediate: $OCSP_NUM"
if [ "$OCSP_NUM" = "unknown" ]; then
    echo "  [WARN] Could not detect OCSP number from issuer"
    echo "         Issuer: $LEAF_ISSUER"
else
    echo "  Download URL: https://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%20${OCSP_NUM}.crt"
fi

# ---- Phase 5: Trust Store Check ----
echo ""
echo "[Phase 5] Trust Store Inventory"
echo "-------------------------------"

# Detect trust store location
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    TRUST_STORE="/etc/ssl/certs/ca-certificates.crt"
elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    TRUST_STORE="/etc/pki/tls/certs/ca-bundle.crt"
elif [ -f /var/lib/ca-certificates/ca-bundle.pem ]; then
    TRUST_STORE="/var/lib/ca-certificates/ca-bundle.pem"
elif [ -f /etc/ssl/ca-bundle.pem ]; then
    TRUST_STORE="/etc/ssl/ca-bundle.pem"
else
    TRUST_STORE="unknown"
fi
echo "  Trust store: $TRUST_STORE"

# Check for DigiCert Global Root G2
if [ "$TRUST_STORE" != "unknown" ]; then
    if awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' "$TRUST_STORE" 2>/dev/null | grep -qi "DigiCert Global Root G2"; then
        echo "  [OK]   DigiCert Global Root G2"
    else
        echo "  [MISS] DigiCert Global Root G2"
    fi

    if awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' "$TRUST_STORE" 2>/dev/null | grep -qi "Microsoft TLS RSA Root G2"; then
        echo "  [OK]   Microsoft TLS RSA Root G2 (B5EE)"
    else
        echo "  [MISS] Microsoft TLS RSA Root G2 (B5EE) - cross-signed intermediate"
        echo "         Download: http://caissuers.microsoft.com/pkiops/certs/Microsoft%20TLS%20RSA%20Root%20G2%20-%20xsign.crt"
    fi

    if [ "$OCSP_NUM" != "unknown" ]; then
        if awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' "$TRUST_STORE" 2>/dev/null | grep -qi "Microsoft TLS G2 RSA CA OCSP $OCSP_NUM"; then
            echo "  [OK]   Microsoft TLS G2 RSA CA OCSP $OCSP_NUM"
        else
            echo "  [MISS] Microsoft TLS G2 RSA CA OCSP $OCSP_NUM - OCSP responder intermediate"
            echo "         Download: https://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%20${OCSP_NUM}.crt"
        fi
    fi
fi

# ---- Phase 6: Connectivity Check ----
echo ""
echo "[Phase 6] AIA / CRL / OCSP Endpoint Connectivity"
echo "-------------------------------------------------"

declare -A TARGETS
TARGETS=(
    ["AIA: cacerts.digicert.com"]="cacerts.digicert.com"
    ["AIA: caissuers.microsoft.com"]="caissuers.microsoft.com"
    ["AIA: www.microsoft.com"]="www.microsoft.com"
    ["CRL: crl3.digicert.com"]="crl3.digicert.com"
    ["CRL: crl4.digicert.com"]="crl4.digicert.com"
    ["OCSP: ocsp.digicert.com"]="ocsp.digicert.com"
    ["OCSP: oneocsp.microsoft.com"]="oneocsp.microsoft.com"
)

BLOCKED=0
for label in "${!TARGETS[@]}"; do
    host="${TARGETS[$label]}"
    if curl -s --connect-timeout 5 -o /dev/null "http://$host" 2>/dev/null; then
        echo "  [+] $label"
    else
        echo "  [-] $label - BLOCKED"
        BLOCKED=$((BLOCKED + 1))
    fi
done

# ---- Phase 7: Summary & Fix Commands ----
echo ""
echo "====================================================="
echo "[Summary]"
echo "====================================================="

if [ "$CHAIN_OK" = true ] && [ "$BLOCKED" -eq 0 ]; then
    echo "  ALL CHECKS PASSED"
    echo "  IMDS attestation certificate chain is healthy."
else
    if [ "$CHAIN_OK" = false ]; then
        echo ""
        echo "  CERTIFICATE CHAIN FAILED - Install missing certificates:"
        echo ""

        # Detect distro
        if [ -f /etc/os-release ]; then
            . /etc/os-release
        fi

        case "${ID:-unknown}" in
            ubuntu|debian)
                echo "  Distribution: $ID (use update-ca-certificates)"
                echo ""
                echo "  # Install cross-signed intermediate (B5EE):"
                echo "  sudo curl -s -o /tmp/b5ee.der \\"
                echo "    'http://caissuers.microsoft.com/pkiops/certs/Microsoft%20TLS%20RSA%20Root%20G2%20-%20xsign.crt'"
                echo "  sudo openssl x509 -in /tmp/b5ee.der -inform DER \\"
                echo "    -out /usr/local/share/ca-certificates/microsoft-tls-rsa-root-g2.crt"
                echo ""
                echo "  # Install OCSP intermediate (replace $OCSP_NUM if different):"
                echo "  sudo curl -s -o /tmp/ocsp.der \\"
                echo "    'https://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%20${OCSP_NUM}.crt'"
                echo "  sudo openssl x509 -in /tmp/ocsp.der -inform DER \\"
                echo "    -out /usr/local/share/ca-certificates/microsoft-tls-g2-rsa-ca-ocsp.crt"
                echo ""
                echo "  sudo update-ca-certificates"
                ;;
            rhel|centos|ol|almalinux|rocky|mariner|azurelinux)
                echo "  Distribution: $ID (use update-ca-trust)"
                echo ""
                echo "  # Install cross-signed intermediate (B5EE):"
                echo "  sudo curl -s -o /tmp/b5ee.der \\"
                echo "    'http://caissuers.microsoft.com/pkiops/certs/Microsoft%20TLS%20RSA%20Root%20G2%20-%20xsign.crt'"
                echo "  sudo openssl x509 -in /tmp/b5ee.der -inform DER \\"
                echo "    -out /etc/pki/ca-trust/source/anchors/microsoft-tls-rsa-root-g2.crt"
                echo ""
                echo "  # Install OCSP intermediate (replace $OCSP_NUM if different):"
                echo "  sudo curl -s -o /tmp/ocsp.der \\"
                echo "    'https://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%20${OCSP_NUM}.crt'"
                echo "  sudo openssl x509 -in /tmp/ocsp.der -inform DER \\"
                echo "    -out /etc/pki/ca-trust/source/anchors/microsoft-tls-g2-rsa-ca-ocsp.crt"
                echo ""
                echo "  sudo update-ca-trust"
                ;;
            sles|opensuse*)
                echo "  Distribution: $ID (use update-ca-certificates)"
                echo ""
                echo "  # Install cross-signed intermediate (B5EE):"
                echo "  sudo curl -s -o /tmp/b5ee.der \\"
                echo "    'http://caissuers.microsoft.com/pkiops/certs/Microsoft%20TLS%20RSA%20Root%20G2%20-%20xsign.crt'"
                echo "  sudo openssl x509 -in /tmp/b5ee.der -inform DER \\"
                echo "    -out /usr/share/pki/trust/anchors/microsoft-tls-rsa-root-g2.crt"
                echo ""
                echo "  # Install OCSP intermediate (replace $OCSP_NUM if different):"
                echo "  sudo curl -s -o /tmp/ocsp.der \\"
                echo "    'https://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%20${OCSP_NUM}.crt'"
                echo "  sudo openssl x509 -in /tmp/ocsp.der -inform DER \\"
                echo "    -out /usr/share/pki/trust/anchors/microsoft-tls-g2-rsa-ca-ocsp.crt"
                echo ""
                echo "  sudo update-ca-certificates"
                ;;
            *)
                echo "  Distribution: $ID (unknown - check your distro's cert management docs)"
                echo "  Download certs from: https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details"
                ;;
        esac
    fi

    if [ "$BLOCKED" -gt 0 ]; then
        echo ""
        echo "  CONNECTIVITY ISSUES ($BLOCKED endpoint(s) blocked):"
        echo "    Configure firewall to allow port 80 outbound to"
        echo "    AIA, CRL, and OCSP endpoints listed above."
        echo "    Reference: https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details#certificate-downloads-and-revocation-lists"
    fi
fi

echo ""
echo "Chain: DigiCert Global Root G2 > Microsoft TLS RSA Root G2 (cross-sign) > OCSP Intermediate > Leaf"
echo "Additional Information: https://aka.ms/AzVmIMDSValidation"
echo "Script completed."
