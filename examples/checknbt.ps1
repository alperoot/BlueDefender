try
{
    Get-ChildItem -Path HKLM:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces -ErrorAction Stop `
    | Get-ItemProperty -Name "NetbiosOptions" -ErrorAction Stop | ConvertTo-Json
}
catch
{
    Write-Output "BULUNAMADI"
}