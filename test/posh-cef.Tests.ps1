<#
$ModuleManifestName = 'posh-cef.psd1'
$ModuleManifestPath = "$PSScriptRoot\..\$ModuleManifestName"

Describe 'Module Manifest Tests' {
    It 'Passes Test-ModuleManifest' {
        Test-ModuleManifest -Path $ModuleManifestPath
        $? | Should Be $true
    }
}
#>



$Collection = @()

#$PipelinInput = New-Object -TypeName PSObject -Property ([ordered]@{'DeviceVendor'='Contoso';'DeviceProduct'='MyPowershellScript';'DeviceVersion'='1.0';'DeviceEventClassId'='Alert';'Name'='Something bad was detected.';'Severity'=10;'externalId'=12345;'dmac'='01-23-45-67-89-AF';'src'='192.168.1.1';'deviceDirection'='Outbound';'spriv'='Administrator';'Type'='Base';'In'=6213467;'cfp1'=3.141592653589;'CustomExtensionRawString'='key=value'})
$Collection += New-Object -TypeName PSObject -Property ([ordered]@{'DeviceVendor'='Contoso';'DeviceProduct'='MyPowershellScript';'DeviceVersion'='1.0';'DeviceEventClassId'='Alert1';'Name'='Foo was detected.';'Severity'='9';'act'='Blocked';'externalId'='12345'})
$Collection += New-Object -TypeName PSObject -Property ([ordered]@{'DeviceVendor'='Contoso';'DeviceProduct'='MyPowershellScript';'DeviceVersion'='1.0';'DeviceEventClassId'='Alert2';'Name'='Bar was detected.';'Severity'='10';'deviceAction'='Blocked';'externalId'='12345'})

$Collection | FT
$Collection | New-CEFMessage | Write-Host -ForegroundColor Cyan
$Collection | %{New-CEFMessage -DeviceVendor $_.DeviceVendor -DeviceProduct $_.DeviceProduct -DeviceVersion $_.DeviceVersion -DeviceEventClassId $_.DeviceEventClassId -Name $_.Name -Severity $_.Severity -externalId 12345 -dmac '01-23-45-67-89-AF' -CustomExtensionRawString 'key=value' -deviceDirection Inbound } | Write-Host -ForegroundColor Yellow
$Collection | New-CEFMessage -DeviceVendor 'JaredP' -DeviceProduct 'MyScript' -DeviceVersion '2.0' -DeviceEventClassId 'Detection' -Severity 8 -externalId 12345 -dmac '01-23-45-67-89-AF' -CustomExtensionRawString 'key=value' -deviceDirection Outbound  | Write-Host -ForegroundColor Red


New-CEFMessage -DeviceVendor 'Contoso' -DeviceProduct 'MyPowershellScript' -DeviceVersion '1.0' -DeviceEventClassId 'Alert' -Name 'Bad Thing Detected' -Severity 10 -externalId 12345 -dmac '01-23-45-67-89-AF' -src 192.168.1.1 -deviceDirection Outbound -spriv Administrator -Type Base -In 6213467 -cfp1 3.141592653589 -CustomExtensionRawString 'key=value' |  Write-Host -ForegroundColor Cyan




