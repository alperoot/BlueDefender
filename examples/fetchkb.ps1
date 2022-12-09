try {
    Invoke-WebRequest "https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx" -OutFile "resources\bulletin-temp.xlsx"
}
catch {
    Write-Output "ISTEKHATASI"
    break
}

# Get the file hashes
$hashSrc = Get-FileHash "resources\bulletin.xlsx" -Algorithm "SHA256"
$hashDest = Get-FileHash "resources\bulletin-temp.xlsx" -Algorithm "SHA256"

# Compare the hashes & note this in the log
If ($hashSrc.Hash -ne $hashDest.Hash)
{
    Remove-Item -Path "resources\bulletin.xlsx"
    Rename-Item -Path "resources\bulletin-temp.xlsx" -NewName "bulletin.xlsx"
    Write-Output "GUNCELLENDI"
}
Else {
    Remove-Item -Path "resources\bulletin-temp.xlsx"
    Write-Output "GUNCEL"
}