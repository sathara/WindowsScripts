# Define parameters
$certPath = "\\networkpath\to\newcertificate.pfx" # Network path to the new PFX file
$certPassword = ConvertTo-SecureString -String "new_certificate_password" -Force -AsPlainText # Password for the new PFX file
$oldCertThumbprint = "OLD_CERTIFICATE_THUMBPRINT" # Thumbprint of the old certificate to replace
$newCertStore = "My" # Certificate store name (usually "My" for personal certificates)
$servers = @("Server1", "Server2", "Server3") # List of remote server names or IPs

# Script block to execute on each remote server
$updateCertScript = {
    param ($certPath, $certPassword, $oldCertThumbprint, $newCertStore)

    # Import the new certificate
    $newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $newCert.Import($certPath, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet)

    # Install the new certificate in the local machine's personal store
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $newCertStore, "LocalMachine"
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($newCert)
    $store.Close()

    # Get the new certificate thumbprint
    $newCertThumbprint = $newCert.Thumbprint
    Write-Output "New certificate installed with thumbprint: $newCertThumbprint on $env:COMPUTERNAME"

    # Load the IIS module
    Import-Module WebAdministration

    # Iterate through all IIS sites and update only bindings with the old certificate thumbprint
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        $bindings = Get-WebBinding -Name $site.Name -Protocol "https"
        foreach ($binding in $bindings) {
            # Check if the current binding uses the old certificate
            $sslCertHash = $binding.CertificateHash
            if ($sslCertHash -eq $oldCertThumbprint) {
                # Update binding to use the new certificate
                $binding.RemoveSslCertificate()
                $binding.AddSslCertificate($newCertThumbprint, "LocalMachine")
                Write-Output "Updated SSL certificate for site: $site.Name on $env:COMPUTERNAME to new certificate thumbprint: $newCertThumbprint"
            }
        }
    }

    Write-Output "SSL certificate update complete for all sites on $env:COMPUTERNAME."
}

# Execute the script block on each remote server
foreach ($server in $servers) {
    Write-Output "Connecting to $server..."
    Invoke-Command -ComputerName $server -ScriptBlock $updateCertScript -ArgumentList $certPath, $certPassword, $oldCertThumbprint, $newCertStore -Credential (Get-Credential)
    Write-Output "Completed SSL update on $server."
}
