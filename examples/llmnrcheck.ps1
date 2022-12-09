try {
    Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast | ConvertTo-Json
}
catch {
    Write-Output "HATA"
}