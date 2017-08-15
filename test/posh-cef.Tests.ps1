
$ModuleManifestName = 'posh-cef.psd1'
$ModuleManifestPath = "$PSScriptRoot\..\$ModuleManifestName"

Describe 'Module Manifest Tests' {
    It 'Passes Test-ModuleManifest' {
        Test-ModuleManifest -Path $ModuleManifestPath
        $? | Should Be $true
    }
}



<#
$ExpectedResult = 'CEF:0|Contoso|MyPowershellScript|1.0|Alert|Something bad was detected.|10|externalId=12345 src=192.168.1.1 deviceDirection=1 act=Blocked spriv=Administrator type=0 in=6213467 dmac=01:23:45:67:89:AF cfp1=3.141593 key=value'

$TestCollection = @()
$TestCollection += New-Object -TypeName PSObject -Property ([ordered]@{'DeviceVendor'='Contoso';'DeviceProduct'='MyPowershellScript';'DeviceVersion'='1.0';'DeviceEventClassId'='Alert';'Name'='Something bad was detected.';'Severity'=10;'externalId'='12345';'src'='192.168.1.1';'deviceDirection'='Outbound';'act'='Blocked';'spriv'='Administrator';'Type'='Base';'In'=6213467;'dmac'='01-23-45-67-89-AF';'cfp1'=3.141592653589;'CustomExtensionRawString'='key=value'})


Describe 'New-CEFMessage' {
    It 'Properly outputs CEF formatted message' {
        $Result = New-CEFMessage -DeviceVendor 'Contoso' -DeviceProduct 'MyPowershellScript' -DeviceVersion '1.0' -DeviceEventClassId 'Alert' -Name 'Something bad was detected.' -Severity 10 -externalId 12345 -src 192.168.1.1 -deviceDirection Outbound -act 'Blocked' -spriv 'Administrator' -Type Base -In 6213467 -dmac '01-23-45-67-89-AF' -cfp1 3.141592653589 -CustomExtensionRawString 'key=value'
        $Result | Should Be $ExpectedResult
    }

    It 'Accepts input via ForEach-Object' {
        $Result = $TestCollection | New-CEFMessage
        $Result | Should Be $ExpectedResult
    }
}



$TestCollection | New-CEFMessage -Verbose
$TestCollection
$TestCollection | %{$_}



#$TestCollection | %{New-CEFMessage -DeviceVendor $_.DeviceVendor -DeviceProduct $_.DeviceProduct -DeviceVersion $_.DeviceVersion -DeviceEventClassId $_.DeviceEventClassId -Name $_.Name -Severity $_.Severity -externalId 12345 -dmac '01-23-45-67-89-AF' -CustomExtensionRawString 'key=value' -deviceDirection Inbound }
#$TestCollection | %{New-CEFMessage -DeviceVendor $_.DeviceVendor -DeviceProduct $_.DeviceProduct -DeviceVersion $_.DeviceVersion -DeviceEventClassId $_.DeviceEventClassId -Name $_.Name -Severity $_.Severity -externalId $_.externalId -dmac $_.dmac -src $_.src -deviceDirection $_.deviceDirection -act $_.act -spriv $_.spriv -Type $_.Type -In $_.In -cfp1 $_.cfp1 -CustomExtensionRawString $_.CustomExtensionRawString}

#$TestCollection | New-CEFMessage -DeviceVendor 'JaredP' -DeviceProduct 'MyScript' -DeviceVersion '2.0' -DeviceEventClassId 'Detection' -Severity 8 -externalId 12345 -dmac '01-23-45-67-89-AF' -CustomExtensionRawString 'key=value' -deviceDirection Outbound  | Write-Host -ForegroundColor Red




#>


