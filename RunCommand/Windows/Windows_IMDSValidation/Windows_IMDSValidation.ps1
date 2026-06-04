<# 
Disclaimer:
    The sample scripts are not supported under any Microsoft standard support program or service.
    The sample scripts are provided AS IS without warranty of any kind.
    Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose.
    The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
    In no event shall Microsoft, its authors, or anyone else involved in the creation, production,
    or delivery of the scripts be liable for any damages whatsoever (including, without limitation,
    damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
    arising out of the use of or inability to use the sample scripts or documentation,
    even if Microsoft has been advised of the possibility of such damages.

    For more details, see: https://aka.ms/AzVmIMDSValidation

.SYNOPSIS
    Validates Azure Instance Metadata Service (IMDS) attestation and certificate chain on Azure VMs.

.DESCRIPTION
    This script performs the following checks:
    Phase 1 - Verifies the IMDS endpoint (169.254.169.254) is reachable
    Phase 2 - Fetches the attested document and extracts the signing certificate
    Phase 3 - Builds the certificate chain and identifies the EXACT certificate
              that is missing or invalid (not just the leaf cert issuer)
    Phase 4 - Inventories the local certificate stores for all IMDS-relevant certs
    Phase 5 - Tests TCP connectivity to AIA, CRL, and OCSP endpoints
    Phase 6 - Provides an actionable summary with specific download URLs

.NOTES
    Requires administrator privileges.
    Tested on Windows Server 2016, 2019, 2022, 2025.
    Run via Azure Run Command or locally in an elevated PowerShell session.

.EXAMPLE
    Run as administrator:
    PS> .\Windows_IMDSValidation.ps1

.EXAMPLE
    Run with auto-fix (downloads and installs missing certificates, then re-validates):
    PS> .\Windows_IMDSValidation.ps1 -AutoFix

.PARAMETER AutoFix
    When specified, the script attempts to download and install missing intermediate
    certificates, then re-validates the chain. Default is diagnostic-only (no changes).
#>

param(
    [switch]$AutoFix = $false
)

# ---- Display banner ----------------------------------------------------------
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Azure IMDS Attestation Certificate Chain Validator"   -ForegroundColor Cyan
Write-Host " Reference: https://aka.ms/AzVmIMDSValidation"        -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# ---- Safety checks -----------------------------------------------------------
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[FAIL] Please run this script as Administrator." -ForegroundColor Red
        exit 1
    }
}
Assert-Admin

# ---- Known IMDS Attestation Certificate Chain --------------------------------
# As of Jan 2026: IMDS uses OCSP responder certs chained through a cross-signed
# intermediate to the DigiCert Global Root G2.
# Chain: Leaf -> OCSP Intermediate -> Cross-signed Intermediate -> Root
$KnownCerts = @(
    [PSCustomObject]@{
        CN          = "DigiCert Global Root G2"
        Thumbprint  = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
        Type        = "Root CA"
        Store       = "Root"
        Location    = "LocalMachine"
        DownloadUrl = "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"
    },
    [PSCustomObject]@{
        CN          = "Microsoft TLS RSA Root G2"
        Thumbprint  = "B5EE89E77326AB2BF1775BD99C19A28947FF8184"
        Type        = "Cross-signed Intermediate (NOT a root despite its name)"
        Store       = "CA"
        Location    = "LocalMachine"
        DownloadUrl = "http://caissuers.microsoft.com/pkiops/certs/Microsoft%20TLS%20RSA%20Root%20G2%20-%20xsign.crt"
    },
    [PSCustomObject]@{
        CN          = "Microsoft TLS G2 RSA CA OCSP 04"
        Thumbprint  = "DA6D0400641B45AECC595D24E5037AA6BC09C358"
        Type        = "OCSP Responder Intermediate"
        Store       = "CA"
        Location    = "LocalMachine"
        DownloadUrl = "https://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2004.crt"
    }
)

# ---- Phase 1: IMDS Reachability ---------------------------------------------
Write-Host "`n[Phase 1] IMDS Endpoint Reachability" -ForegroundColor Cyan
Write-Host "-------------------------------------" -ForegroundColor Cyan
try {
    $tcp = Test-NetConnection -ComputerName 169.254.169.254 -Port 80 -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) {
        Write-Host "  [PASS] 169.254.169.254:80 is reachable" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] 169.254.169.254:80 is NOT reachable" -ForegroundColor Red
        Write-Host "  Action: Check routing table, firewall, and proxy settings." -ForegroundColor Yellow
        Write-Host "  Reference: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/windows/windows-vm-imds-connection" -ForegroundColor Yellow
        Write-Host "`nScript cannot continue without IMDS connectivity." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "  [FAIL] Network test error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ---- Phase 2: Attestation Fetch ---------------------------------------------
Write-Host "`n[Phase 2] IMDS Attested Document" -ForegroundColor Cyan
Write-Host "--------------------------------" -ForegroundColor Cyan
try {
    $attestedDoc = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET `
        -Uri http://169.254.169.254/metadata/attested/document?api-version=2018-10-01
    $signature = [System.Convert]::FromBase64String($attestedDoc.signature)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]($signature)

    Write-Host "  [PASS] Attested document retrieved successfully" -ForegroundColor Green
    Write-Host "  Leaf Subject   : $($cert.Subject)"
    Write-Host "  Leaf Issuer    : $($cert.Issuer)"
    Write-Host "  Leaf Thumbprint: $($cert.Thumbprint)"
    Write-Host "  Valid          : $($cert.NotBefore.ToString('yyyy-MM-dd')) to $($cert.NotAfter.ToString('yyyy-MM-dd'))"
} catch {
    Write-Host "  [FAIL] Cannot retrieve attested document: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Action: Verify IMDS endpoint connectivity and VM configuration." -ForegroundColor Yellow
    Write-Host "  Reference: https://aka.ms/AzVmIMDSValidation" -ForegroundColor Yellow
    exit 1
}

# ---- Phase 3: Certificate Chain Validation -----------------------------------
Write-Host "`n[Phase 3] Certificate Chain Validation" -ForegroundColor Cyan
Write-Host "--------------------------------------" -ForegroundColor Cyan

$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
$chainBuilt = $chain.Build($cert)

$chainErrors = @()

Write-Host "`n  Chain Elements ($($chain.ChainElements.Count) certificates found):"
for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
    $element = $chain.ChainElements[$i]
    $elCert = $element.Certificate
    $elStatus = $element.ChainElementStatus

    if ($elStatus.Count -eq 0) {
        Write-Host "  [$i] [OK]   $($elCert.Subject)" -ForegroundColor Green
        Write-Host "             Thumbprint: $($elCert.Thumbprint)"
    } else {
        Write-Host "  [$i] [FAIL] $($elCert.Subject)" -ForegroundColor Red
        Write-Host "             Thumbprint: $($elCert.Thumbprint)"
        Write-Host "             Issuer    : $($elCert.Issuer)"
        foreach ($s in $elStatus) {
            $statusInfo = "$($s.StatusInformation)".Trim()
            Write-Host "             Status    : $($s.Status) - $statusInfo" -ForegroundColor Yellow
        }

        # Identify which cert is ACTUALLY missing by checking the issuer
        $issuerCN = ($elCert.Issuer -replace 'CN=','').Split(',')[0].Trim()
        $knownIssuer = $KnownCerts | Where-Object { $_.CN -eq $issuerCN }
        if ($knownIssuer) {
            Write-Host "             >> The issuer certificate may be missing:" -ForegroundColor Red
            Write-Host "                Name    : $($knownIssuer.CN)" -ForegroundColor Yellow
            Write-Host "                Type    : $($knownIssuer.Type)" -ForegroundColor Yellow
            Write-Host "                Download: $($knownIssuer.DownloadUrl)" -ForegroundColor Yellow
            Write-Host "                Store   : $($knownIssuer.Location)\$($knownIssuer.Store)" -ForegroundColor Yellow
        }

        $chainErrors += [PSCustomObject]@{
            Index   = $i
            Subject = $elCert.Subject
            Issuer  = $elCert.Issuer
            Status  = ($elStatus | ForEach-Object { $_.Status }) -join ', '
        }
    }
}

if ($chain.ChainStatus.Count -gt 0) {
    Write-Host "`n  Overall chain status:" -ForegroundColor Yellow
    foreach ($s in $chain.ChainStatus) {
        $statusInfo = "$($s.StatusInformation)".Trim()
        Write-Host "    $($s.Status): $statusInfo" -ForegroundColor Yellow
    }
}

if ($chainBuilt -and $chainErrors.Count -eq 0) {
    Write-Host "`n  [PASS] Certificate chain validated successfully." -ForegroundColor Green
} else {
    Write-Host "`n  [FAIL] Certificate chain validation failed." -ForegroundColor Red
}

# ---- Phase 4: Certificate Store Inventory ------------------------------------
Write-Host "`n[Phase 4] Certificate Store Inventory" -ForegroundColor Cyan
Write-Host "-------------------------------------" -ForegroundColor Cyan

# Build the check list from ACTUAL chain certs (dynamic) merged with known certs.
# IMDS rotates OCSP intermediates (02, 04, 06, 08, 10, 12, 14, 16), so we check
# whatever the VM is actually using, not just hardcoded thumbprints.
$certsToCheck = @()

# Add certs discovered in the actual chain (skip the leaf at index 0)
if ($chain.ChainElements.Count -gt 1) {
    for ($ci = 1; $ci -lt $chain.ChainElements.Count; $ci++) {
        $ec = $chain.ChainElements[$ci].Certificate
        $cn = ($ec.Subject -replace 'CN=','').Split(',')[0].Trim()

        # Determine expected store
        $expectedStore = "CA"
        if ($ec.Subject -eq $ec.Issuer -or $cn -match "Root G[23]?$" -and $cn -notmatch "TLS RSA Root") {
            $expectedStore = "Root"
        }
        $knownMatch = $KnownCerts | Where-Object { $_.Thumbprint -eq $ec.Thumbprint }
        if ($knownMatch) {
            $expectedStore = $knownMatch.Store
        }

        $certsToCheck += [PSCustomObject]@{
            CN          = $cn
            Thumbprint  = $ec.Thumbprint
            Type        = if ($knownMatch) { $knownMatch.Type } else { "Chain intermediate (detected)" }
            Store       = $expectedStore
            Location    = "LocalMachine"
            DownloadUrl = if ($knownMatch) { $knownMatch.DownloadUrl } else { "See https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details" }
            Source      = "chain"
        }
    }
}

# Add any known certs not already in the list (covers certs that weren't in this chain)
foreach ($known in $KnownCerts) {
    if (-not ($certsToCheck | Where-Object { $_.Thumbprint -eq $known.Thumbprint })) {
        $certsToCheck += [PSCustomObject]@{
            CN          = $known.CN
            Thumbprint  = $known.Thumbprint
            Type        = $known.Type
            Store       = $known.Store
            Location    = $known.Location
            DownloadUrl = $known.DownloadUrl
            Source      = "known"
        }
    }
}

Write-Host "  Checking $($certsToCheck.Count) certificates (from chain + known list):`n"

$missingCerts = @()

foreach ($chk in $certsToCheck) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($chk.Store, $chk.Location)
    $store.Open("ReadOnly")
    $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $chk.Thumbprint }
    $store.Close()

    $wrongStores = @()
    foreach ($checkStore in @("Root","CA","My","AuthRoot")) {
        if ($checkStore -eq $chk.Store) { continue }
        $s2 = New-Object System.Security.Cryptography.X509Certificates.X509Store($checkStore, $chk.Location)
        $s2.Open("ReadOnly")
        $inWrong = $s2.Certificates | Where-Object { $_.Thumbprint -eq $chk.Thumbprint }
        $s2.Close()
        if ($inWrong) { $wrongStores += "$($chk.Location)\$checkStore" }
    }

    $disStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Disallowed", $chk.Location)
    $disStore.Open("ReadOnly")
    $inDisallowed = $disStore.Certificates | Where-Object { $_.Thumbprint -eq $chk.Thumbprint }
    $disStore.Close()

    $label = if ($chk.Source -eq "chain") { "(active chain)" } else { "(known)" }

    if ($found) {
        Write-Host "  [OK]   $($chk.CN) $label" -ForegroundColor Green
        Write-Host "         Store: $($chk.Location)\$($chk.Store) (correct)"
        Write-Host "         Type : $($chk.Type)"
        if ($wrongStores.Count -gt 0) {
            Write-Host "         [WARN] Also found in: $($wrongStores -join ', ')" -ForegroundColor Yellow
        }
        if ($inDisallowed) {
            Write-Host "         [WARN] Certificate is in the DISALLOWED store!" -ForegroundColor Red
        }
    } else {
        $autoNote = ""
        if ($chainBuilt -and $chk.Source -eq "chain") {
            $autoNote = " (was auto-downloaded via AIA during chain build)"
        }
        Write-Host "  [MISS] $($chk.CN) $label$autoNote" -ForegroundColor $(if ($chk.Source -eq "chain") { "Yellow" } else { "Red" })
        Write-Host "         Expected store: $($chk.Location)\$($chk.Store)"
        Write-Host "         Type          : $($chk.Type)"
        Write-Host "         Download      : $($chk.DownloadUrl)" -ForegroundColor Yellow
        if ($wrongStores.Count -gt 0) {
            Write-Host "         [WARN] Found in WRONG store: $($wrongStores -join ', ')" -ForegroundColor Yellow
        }
        if ($inDisallowed) {
            Write-Host "         [WARN] Certificate is in the DISALLOWED store!" -ForegroundColor Red
        }
        $missingCerts += $chk
    }
}

# Note about auto-download if chain passed but certs missing
if ($chainBuilt -and $missingCerts.Count -gt 0) {
    $autoDownloaded = $missingCerts | Where-Object { $_.Source -eq "chain" }
    if ($autoDownloaded.Count -gt 0) {
        Write-Host "`n  [NOTE] Chain validation PASSED but $($autoDownloaded.Count) cert(s) are not permanently" -ForegroundColor Yellow
        Write-Host "         installed. They were auto-downloaded via AIA at runtime." -ForegroundColor Yellow
        Write-Host "         Install them permanently to avoid failures if AIA is blocked." -ForegroundColor Yellow
    }
}

# ---- Phase 5: Connectivity Check --------------------------------------------
Write-Host "`n[Phase 5] AIA / CRL / OCSP Endpoint Connectivity" -ForegroundColor Cyan
Write-Host "-------------------------------------------------" -ForegroundColor Cyan

$tcpTargets = [ordered]@{
    "AIA (certificate download)" = @(
        "cacerts.digicert.com",
        "cacerts.digicert.cn",
        "cacerts.geotrust.com",
        "caissuers.microsoft.com",
        "www.microsoft.com"
    )
    "CRL (revocation lists)" = @(
        "crl3.digicert.com",
        "crl4.digicert.com",
        "crl.digicert.cn",
        "www.microsoft.com"
    )
    "OCSP (online validation)" = @(
        "ocsp.digicert.com",
        "ocsp.digicert.cn",
        "oneocsp.microsoft.com"
    )
}

$unreachableCount = 0
foreach ($category in $tcpTargets.Keys) {
    Write-Host "`n  $category" -ForegroundColor Magenta
    foreach ($targetHost in $tcpTargets[$category]) {
        try {
            $result = Test-NetConnection -ComputerName $targetHost -Port 80 -WarningAction SilentlyContinue
            if ($result.TcpTestSucceeded) {
                Write-Host "    [+] $targetHost" -ForegroundColor Green
            } else {
                $unreachableCount++
                Write-Host "    [-] $targetHost - BLOCKED" -ForegroundColor Red
            }
        } catch {
            $unreachableCount++
            Write-Host "    [!] $targetHost - ERROR: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ---- Phase 6: Summary & Recommendations -------------------------------------
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "[Summary]" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

if ($chainBuilt -and $chainErrors.Count -eq 0 -and $missingCerts.Count -eq 0 -and $unreachableCount -eq 0) {
    Write-Host "  ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "  IMDS attestation certificate chain is healthy." -ForegroundColor Green
} else {
    if ($missingCerts.Count -gt 0) {
        Write-Host "`n  MISSING CERTIFICATES ($($missingCerts.Count)):" -ForegroundColor Red
        foreach ($mc in $missingCerts) {
            Write-Host "    - $($mc.CN) ($($mc.Type))" -ForegroundColor Yellow
            Write-Host "      Download : $($mc.DownloadUrl)"
            Write-Host "      Install  : $($mc.Location)\$($mc.Store)"
        }
        Write-Host "`n  After installing certificates:" -ForegroundColor Yellow
        Write-Host "    1. Run: fclip.exe  (from C:\Windows\System32)" -ForegroundColor Yellow
        Write-Host "    2. Restart the VM or sign out and sign back in" -ForegroundColor Yellow
        Write-Host "    Reference: https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details?tabs=certificate-authority-chains" -ForegroundColor Yellow
    }

    if (-not $chainBuilt -and $missingCerts.Count -eq 0) {
        Write-Host "`n  CHAIN VALIDATION FAILED (all known certs present):" -ForegroundColor Red
        Write-Host "    Possible causes:" -ForegroundColor Yellow
        Write-Host "      - Certificate in the wrong store (check Phase 4 warnings)" -ForegroundColor Yellow
        Write-Host "      - Certificate is expired" -ForegroundColor Yellow
        Write-Host "      - Certificate is in the Disallowed store" -ForegroundColor Yellow
        Write-Host "      - A newer OCSP intermediate is in use (cert rotation)" -ForegroundColor Yellow
        Write-Host "    Reference: https://aka.ms/AzVmIMDSValidation" -ForegroundColor Yellow
    }

    if ($unreachableCount -gt 0) {
        Write-Host "`n  CONNECTIVITY ISSUES ($unreachableCount endpoint(s) blocked):" -ForegroundColor Red
        Write-Host "    Configure firewall/proxy to allow port 80 outbound to" -ForegroundColor Yellow
        Write-Host "    AIA, CRL, and OCSP endpoints listed above." -ForegroundColor Yellow
        Write-Host "    Reference: https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details#certificate-downloads-and-revocation-lists" -ForegroundColor Yellow
    }
}

Write-Host "`nChain: DigiCert Global Root G2 > Microsoft TLS RSA Root G2 (cross-sign) > OCSP Intermediate > Leaf" -ForegroundColor Cyan
Write-Host "Additional Information: https://aka.ms/AzVmIMDSValidation" -ForegroundColor Cyan
# ---- AutoFix Phase: Download, Install, Re-validate --------------------------
if ($AutoFix -and $missingCerts.Count -gt 0) {
    Write-Host "`n=============================================" -ForegroundColor Magenta
    Write-Host " AutoFix: Attempting certificate remediation" -ForegroundColor Magenta
    Write-Host "=============================================" -ForegroundColor Magenta

    $fixedCount = 0
    $failedCount = 0

    foreach ($mc in $missingCerts) {
        # Skip certs in the Disallowed store — can't auto-fix policy decisions
        $disStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Disallowed", $mc.Location)
        $disStore.Open("ReadOnly")
        $inDisallowed = $disStore.Certificates | Where-Object { $_.Thumbprint -eq $mc.Thumbprint }
        $disStore.Close()
        if ($inDisallowed) {
            Write-Host "`n  [SKIP] $($mc.CN) — in Disallowed store (policy decision, cannot auto-fix)" -ForegroundColor Yellow
            $failedCount++
            continue
        }

        Write-Host "`n  Downloading: $($mc.CN)" -ForegroundColor Cyan
        Write-Host "    URL: $($mc.DownloadUrl)"
        try {
            $tmpPath = "$env:TEMP\imds_cert_$($mc.Thumbprint).crt"
            Invoke-WebRequest -Uri $mc.DownloadUrl -OutFile $tmpPath -UseBasicParsing -TimeoutSec 15
            Write-Host "    [OK] Downloaded" -ForegroundColor Green

            # Install to the correct store
            $targetStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($mc.Store, $mc.Location)
            $targetStore.Open("ReadWrite")
            $newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmpPath)
            $targetStore.Add($newCert)
            $targetStore.Close()

            Write-Host "    [OK] Installed to $($mc.Location)\$($mc.Store)" -ForegroundColor Green
            $fixedCount++

            # Clean up temp file
            Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            $failedCount++
        }
    }

    # Re-validate the chain
    Write-Host "`n  Re-validating certificate chain..." -ForegroundColor Cyan
    $chain2 = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain2.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain2Built = $chain2.Build($cert)

    if ($chain2Built) {
        Write-Host "  [PASS] Certificate chain now validates successfully!" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Certificate chain still fails after remediation." -ForegroundColor Red
        Write-Host "         Review Phase 3 output above for remaining issues." -ForegroundColor Yellow
    }

    # Run fclip.exe if chain now passes
    if ($chain2Built -and (Test-Path "$env:SystemRoot\System32\fclip.exe")) {
        Write-Host "`n  Running fclip.exe to clear activation watermark..." -ForegroundColor Cyan
        try {
            & "$env:SystemRoot\System32\fclip.exe" 2>$null
            Write-Host "  [OK] fclip.exe completed. Sign out and sign back in to clear the watermark." -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] fclip.exe failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host "`n  AutoFix Summary: $fixedCount installed, $failedCount failed/skipped" -ForegroundColor Cyan
} elseif ($AutoFix -and $missingCerts.Count -eq 0) {
    Write-Host "`n  [INFO] AutoFix: No missing certificates to fix." -ForegroundColor Green
}
Write-Host "Script completed.`n" -ForegroundColor Cyan
