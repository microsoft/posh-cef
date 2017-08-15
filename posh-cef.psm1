
enum CEF_Ext_Device_Direction {
    inbound
    outbound
}

enum CEF_Ext_Event_Type {
    Base
    Aggregated
    Correlation
    Action
}

function Format-MacAddress {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # MAC address to be formatted. Can be colon/hyphen/space delimited or not delimited
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 17)]
        [ValidateScript( {$_ -replace (':', '') -replace ('-', '') -replace (' ', '') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("MacAddress", "PhysicalAddress")]
        [string]
        $Address,

        # Optional separator character to use (can be colon ':', hyphen '-', or space ' '). If not specified, no separator will be used.
        [Parameter(Mandatory = $false,
            Position = 1)]
        [ValidateSet(':', '-', ' ')]
        [char]
        $Separator,

        # Specify output in all upper/lower case
        [Parameter(Mandatory = $false,
            Position = 2)]
        [ValidateSet('Upper', 'Lower')]
        [string]
        $Case
    )
    Begin {}

    Process {
        If ($Case -eq 'Upper') {
            $Address = $Address.ToUpper()
            Write-Verbose "Format-MacAddress: Upper case was enforced: $Address"
        }

        If ($Case -eq 'Lower') {
            $Address = $Address.ToLower()
            Write-Verbose "Format-MacAddress: Lower case was enforced: $Address"
        }

        $Address = $Address -replace (':', '') -replace ('-', '') -replace (' ', '')
        Write-Verbose "Format-MacAddress: Colon (:), hyphen (-), and space ( ) separators were removed: $Address"

        $Address = @(($Address[0, 1] -join ''), ($Address[2, 3] -join ''), ($Address[4, 5] -join ''), ($Address[6, 7] -join ''), ($Address[8, 9] -join ''), ($Address[10, 11] -join '')) -join $Separator
        Write-Verbose "Format-MacAddress: Address was reconstructed with specified separator: $Address"

        $Address
    }

    End {}
}

function New-CEFMessage {
    <#
    .Synopsis
        Creates a CEF message string (without a SYSLOG prefix) that will typically be sent via SYSLOG or written to a file

    .DESCRIPTION
        Generate a properly formatted CEF message (CEF version 0 as specified by CommonEventFormatv23.pdf) consisting of mandatory CEF header fields and optional CEF extension fields

    .EXAMPLE
        New-CEFMessage -DeviceVendor 'Contoso' -DeviceProduct 'MyPowershellScript' -DeviceVersion '1.0' -DeviceEventClassId 'Alert' -Name 'Bad Thing Detected' -Severity 10 -externalId 12345 -dmac '01-23-45-67-89-AF' -src 192.168.1.1 -deviceDirection Outbound -spriv Administrator -Type Base -In 6213467 -cfp1 3.141592653589 -CustomExtensionRawString 'key=value'

    .INPUTS
        All parameters can accept input from the pipeline

    .OUTPUTS
        CEF message as a [string]

    .NOTES
        Name: New-CEFMessage
        Author: Jared Poeppelman (powershellshock)

    .LINK
        https://github.com/poshsecurity/posh-cef

    .LINK
        https://github.com/powershellshock
    #>
    [CMDLetBinding()]
    [OutputType([string])]
    Param
    (
        # Specifies the value to use for the "Device Vendor" portion of the CEF message header
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName=$true, HelpMessage = 'String to uniquely identify the vendor of the device or component generating the message')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceVendor,

        # Specifies the value to use for the "Device Product" portion of the CEF message header
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName=$true, HelpMessage = 'String to uniquely identify the product name of the device or component generating the message')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceProduct,

        # Specifies the value to use for the "Device Version" portion of the CEF message header
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName=$true, HelpMessage = 'String to uniquely identify the product version of the device or component generating the message')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceVersion,

        # Specifies the value to use for the "Device Event Class ID" portion of the CEF message header
        [Parameter(Mandatory = $true, Position = 3,ValueFromPipelineByPropertyName=$true,  HelpMessage = 'String to uniquely identify the event type being reported in the message, also known as "Signature ID"')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceEventClassId,

        # Specifies the value to use for the "Name" portion of the CEF message header
        [Parameter(Mandatory = $true, Position = 4, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage = 'String representing a human-readable description of the event; should be general and not include information that is specific to a single instance of the event, such as a source IP')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        # Specifies the severity value from 0 to 10 (0=lowest, 10=highest) to use for the "Severity" portion of the CEF message header
        [Parameter(Mandatory = $true, Position = 5, ValueFromPipelineByPropertyName=$true, HelpMessage = 'String to uniquely identify the vendor of the device or component generating the message')]
        [ValidateRange(0, 10)]
        [Int]
        $Severity,


        #-------------------------------------------------------------------------------
        #----------------------------Optional CEF Extensions----------------------------
        #-------------------------------------------------------------------------------

        #----------------------------enumtype extensions----------------------------
        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The direction of the observed communication. The following values are supported: "Inbound" (translated to integer value of 0) or "Outbound" (translated to integer value of 1)')]
        [ValidateNotNullOrEmpty()]
        [CEF_Ext_Device_Direction]
        $deviceDirection,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Can be "Base", "Aggregated", "Correlation", or "Action" (translated to integer values of  0, 1, 2, or 3 respectively. This field can be omitted for base events (type 0)')]
        [ValidateNotNullOrEmpty()]
        [CEF_Ext_Event_Type]
        $type,

        #----------------------------ipaddress extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=IPv6address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address1")]
        [ipaddress]
        $c6a1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=IPv6address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address2")]
        [ipaddress]
        $c6a2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=IPv6address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address3")]
        [ipaddress]
        $c6a3,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four IPV6 address fields available to map fields that do not apply to any other CEF extension key name (type=IPv6address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomIPv6Address4")]
        [ipaddress]
        $c6a4,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the translated destination address to which the event refers. Example: "192.168.10.1" (type=IPv4address)')]
        [ValidateNotNullOrEmpty()]
        [ipaddress]
        $destinationTranslatedAddress,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the translated device address to which the event refers. Example: "192.168.10.1" (type=IPv4address)')]
        [ValidateNotNullOrEmpty()]
        [ipaddress]
        $deviceTranslatedAddress,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the destination device address to which the event refers. Example: "192.168.10.1" (type=IPv4address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationAddress")]
        [ipaddress]
        $dst,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the device address to which the event refers. Example: "192.168.10.1" (type=IPv4address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceAddress")]
        [ipaddress]
        $dvc,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the translated source address to which the event refers. Example: "192.168.10.1" (type=IPv4address)')]
        [ValidateNotNullOrEmpty()]
        [ipaddress]
        $sourceTranslatedAddress,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the source device address to which the event refers. Example: "192.168.10.1" (type=IPv4address)')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceAddress")]
        [ipaddress]
        $src,

        #----------------------------mac addr extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the destination MAC address to which an event refers. The format is six pairs of hexadecimal numbers which can be separated by colons, hyphens, spaces, or not separated. (type=string)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 17)]
        [ValidateScript( {$_ -replace (':', '') -replace ('-', '') -replace (' ', '') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("destinationMacAddress")]
        [string]
        $dmac,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the device MAC address to which an event refers. The format is six pairs of hexadecimal numbers which can be separated by colons, hyphens, spaces, or not separated. (type=string)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 17)]
        [ValidateScript( {$_ -replace (':', '') -replace ('-', '') -replace (' ', '') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("deviceMacAddress")]
        [string]
        $dvcmac,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the source MAC address to which an event refers. The format is six pairs of hexadecimal numbers which can be separated by colons, hyphens, spaces, or not separated. (type=string)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 17)]
        [ValidateScript( {$_ -replace (':', '') -replace ('-', '') -replace (' ', '') -match {^[A-Fa-f0-9]{12}$}})]
        [Alias("sourceMacAddress")]
        [string]
        $smac,

        #----------------------------int extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of three number fields available to map fields that do not apply to any other CEF extension key name (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomNumber1", "Channel")]
        [int]
        $cn1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of three number fields available to map fields that do not apply to any other CEF extension key name (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomNumber2")]
        [int]
        $cn2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of three number fields available to map fields that do not apply to any other CEF extension key name (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomNumber3")]
        [int]
        $cn3,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A count associated with this event. How many times was this same event observed? Count can be omitted if it is 1 (type=int)')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {$_ -gt 0})]
        [Alias("baseEventCount")]
        [int]
        $cnt,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the translated destination port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0, 65535)]
        [int]
        $destinationTranslatedPort,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The ID number of the destination process associated with the event. For example, if an event contains process ID 105, "105" is the process ID (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationProcessId")]
        [int]
        $dpid,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the destination port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0, 65535)]
        [Alias("destinationPort")]
        [int]
        $dpt,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The ID number of the process on the device that generated the event. For example, if an event was generated by process ID 105, "105" is the process ID (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceProcessId")]
        [int]
        $dvcpid,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom integer field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=int)')]
        [ValidateNotNullOrEmpty()]
        [int]
        $flexNumber1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom integer field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=int)')]
        [ValidateNotNullOrEmpty()]
        [int]
        $flexNumber2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Size of the file (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("fileSize")]
        [int]
        $fsize,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Number of bytes transferred inbound to the destination from the source (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("bytesIn")]
        [int]
        $in,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Size of the old file (type=int)')]
        [ValidateNotNullOrEmpty()]
        [int]
        $oldFileSize,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Number of bytes transferred outbound from the source to the destination (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("bytesOut")]
        [int]
        $out,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the translated source port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0, 65535)]
        [int]
        $sourceTranslatedPort,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The ID number of the source process associated with the event. For example, if an event contains process ID 105, "105" is the process ID (type=int)')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceProcessId")]
        [int]
        $spid,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the source port number to which the event refers (type=int; range=0-65535)')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0, 65535)]
        [Alias("sourcePort")]
        [int]
        $spt,

        #----------------------------datetime extensions----------------------------

        <#
        #----------------------------Timestamps as [datetime] types----------------------------
        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $deviceCustomDate1,


        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $deviceCustomDate2,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("endTime")]
        [datetime]
        $end,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the file was created (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $fileCreateTime,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the file was last modified (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $fileModificationTime,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom timestamp field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $flexDate1,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the old file was created (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $oldFileCreateTime,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the old file was last modified (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        $OldFileModificationTime,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the event related to the activity was received (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceReceiptTime")]
        [datetime]
        $rt,

        [Parameter(ParameterSetName='CEFExtensionFields',ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("startTime")]
        [datetime]
        $start,
        #>

        #----------------------------Timestamps as [string] types----------------------------
        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $deviceCustomDate1,


        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $deviceCustomDate2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("endTime")]
        [string]
        $end,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the file was created (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $fileCreateTime,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the file was last modified (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $fileModificationTime,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom timestamp field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $flexDate1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the old file was created (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $oldFileCreateTime,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the old file was last modified (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $OldFileModificationTime,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Time when the event related to the activity was received (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceReceiptTime")]
        [string]
        $rt,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of two timestamp fields available to map fields that do not apply to any other CEF extension key name (type=datetime)')]
        [ValidateNotNullOrEmpty()]
        [Alias("startTime")]
        [string]
        $start,

        #----------------------------float extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint1")]
        [float]
        $cfp1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint2")]
        [float]
        $cfp2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint3")]
        [float]
        $cfp3,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of four floating point fields available to map fields that do not apply to any other CEF extension key name (type=float)')]
        [ValidateNotNullOrEmpty()]
        [Alias("deviceCustomFloatingPoint4")]
        [float]
        $cfp4,

        #----------------------------String extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Action taken by the device (full name=deviceAction; type=string; max length=63)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 63)]
        [Alias("deviceAction", "Action")]
        [String]
        $act,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Application level protocol, example values are: HTTP, HTTPS, SSHv2, Telnet, POP, IMAP, IMAPS, etc. (type=string; max length=31)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 31)]
        [Alias("applicationProtocol")]
        [String]
        $app,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 4000)]
        [string]
        [Alias("deviceCustomString1", "RuleNumber", "AclNumber", "VirusName", "Relay")]
        $cs1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 4000)]
        [Alias("deviceCustomString2", "SignatureVersion", "EngineVersion", "SSID")]
        [string]
        $cs2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 4000)]
        [Alias("deviceCustomString3")]
        [string]
        $cs3,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 4000)]
        [Alias("deviceCustomString4")]
        [string]
        $cs4,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 4000)]
        [Alias("deviceCustomString5")]
        [string]
        $cs5,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'One of six string fields available to map fields that do not apply to any other CEF extension key name (type=string; max length=4000)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 4000)]
        [Alias("deviceCustomString6")]
        [string]
        $cs6,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The DNS domain part of the complete fully qualified domain name (FQDN) of the destination (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [String]
        $destinationDnsDomain,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The service targeted by this event. Example: "sshd" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [String]
        $destinationServiceName,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A name that uniquely identifies the device generating this event (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [string]
        $deviceExternalId,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The facility generating this event. For example, Syslog has an explicit facility associated with every event (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $deviceFacility,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Interface on which the packet or data entered the device (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $deviceInboundInterface,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The Windows domain name of the device address (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [string]
        $deviceNtDomain,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Interface on which the packet or data left the device (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $deviceOutboundInterface,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Unique identifier for the payload associated with the event (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $devicePayloadId,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Process name associated with the event. An example might be the process generating the syslog entry in UNIX (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $deviceProcessName,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the destination to which an event refers. The format should be a fully qualified domain name associated with the destination node, if available  (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("destinationHostName")]
        [string]
        $dhost,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The Windows domain name of the destination address (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [Alias("destinationNtDomain")]
        [string]
        $dntdom,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The typical values are: "Administrator", "User", and "Guest". This identifies the privilege level of the user on the destination system. For example, activity executed on the root user would be identified with value of "Administrator"')]
        [ValidateNotNullOrEmpty()]
        [Alias("destinationUserPrivileges")]
        [string]
        $dpriv,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The name of the destination process with which the event is associated. For example, "telnetd" or "sshd" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("destinationProcessName")]
        [string]
        $dproc,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The timezone for the device generating the event (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [Alias("deviceTimeZone")]
        [string]
        $dtz,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the destination user by ID. For example, in UNIX, the root user has the uid of 0 (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("destinationUserId")]
        [string]
        $duid,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the username associated with the destination system. For example, with email related events the recipient is a candidate to put into destinationUserName. (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("destinationUserName", "Recipient")]
        [string]
        $duser,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Fully qualified domain name associated with the device, if available (type=string; max length=100)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 100)]
        [Alias("deviceHostName")]
        [string]
        $dvchost,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The unique event identifier used by an originating device (type=string; max length=40)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 40)]
        [string]
        $externalId,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The hash of the file (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [ValidateScript( {$_ -match {^[A-Fa-f0-9]{32}$} -or $_ -match {^[A-Fa-f0-9]{40}} -or $_ -match {^[A-Fa-f0-9]{56}} -or $_ -match {^[A-Fa-f0-9]{64}} -or $_ -match {^[A-Fa-f0-9]{80}} -or $_ -match {^[A-Fa-f0-9]{96}} -or $_ -match {^[A-Fa-f0-9]{128}} })]
        [string]
        $fileHash,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'An ID associated with a file, could be the inode (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $fileId,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Full path to the file, including file name itself. Example: C:\Program Files\WindowsNT\Accessories\wordpad.exe or /usr/bin/zip (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $filePath,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Permissions of the file (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $filePermission,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Type of the file, such as pipe, socket, etc (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $fileType,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom string field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $flexstring1,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom string field typically reserved for customer use and should not be set by vendors unless necessary. Use all flex fields sparingly and seek a more specific field when possible (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $flexstring2,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Name of the file only, without its path (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("fileName")]
        [string]
        $fname,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'An arbitrary message giving more details about the event. Multi-line entries can be produced by using \n as the new line separator (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("message")]
        [string]
        $msg,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The hash of the old file (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [ValidateScript( {$_ -match {^[A-Fa-f0-9]{32}$} -or $_ -match {^[A-Fa-f0-9]{40}} -or $_ -match {^[A-Fa-f0-9]{56}} -or $_ -match {^[A-Fa-f0-9]{64}} -or $_ -match {^[A-Fa-f0-9]{80}} -or $_ -match {^[A-Fa-f0-9]{96}} -or $_ -match {^[A-Fa-f0-9]{128}} })]
        [string]
        $oldFileHash,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'An ID associated with the old file, could be the inode (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $oldFileId,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Name of the old file, without its path (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $oldFileName,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Full path to the old file, including file name itself. Example: C:\Program Files\WindowsNT\Accessories\wordpad.exe or /usr/bin/zip (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $oldFilePath,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Permissions of the old file (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $oldFilePermission,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Type of the old file, such as pipe, socket, etc (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $oldFileType,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The outcome of the event, typically "success" or "failure" (type=string; max length=63)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 63)]
        [Alias("eventOutcome")]
        [string]
        $outcome,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the layer-4 protocol used, such as TCP, UDP, ICMP, GRE, etc. (type=string; max length=31)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 31)]
        [Alias("transportProtocol")]
        [string]
        $proto,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The reason an event was generated, such as "Bad password" or "Unknown user" or return code like "0x1234" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $reason,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'In the case of an HTTP request, this field contains the URL accessed, such as "https://site.example/vdir/resource.html" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("requestUrl")]
        [string]
        $request,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The user-agent associated with the request (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $requestClientApplication,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Description of the content from which the request originated, such as "HTTP Referrer" (type=string; max length=2048)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 2048)]
        [string]
        $requestContext,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Cookies associated with the request (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $requestCookies,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Method used to access a URL, such as "GET" or "POST" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $requestMethod,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the source system to which an event refers. The format should be a fully qualified domain name associated with the source node, if available  (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("sourceHostName")]
        [string]
        $shost,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The Windows domain name of the source address (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [Alias("sourceNtDomain")]
        [string]
        $sntdom,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The DNS domain part of the complete fully qualified domain name (FQDN) of the source (type=string; max length=255)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 255)]
        [String]
        $sourceDnsDomain,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The service responsible for generating the event (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [String]
        $sourceServiceName,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The typical values are: "Administrator", "User", and "Guest". This identifies the privilege level of the user on the source system. For example, activity executed on the root user would be identified with value of "Administrator"')]
        [ValidateNotNullOrEmpty()]
        [Alias("sourceUserPrivileges")]
        [string]
        $spriv,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'The name of the source process with which the event is associated. For example, "telnet" or "ssh" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("sourceProcessName")]
        [string]
        $sproc,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the source user by ID. For example, in UNIX, the root user has the uid of 0 (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("sourceUserId")]
        [string]
        $suid,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Identifies the username associated with the source system. For example, with email related events the sender is a candidate to put into sourceUserName. (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("sourceUserName", "Sender")]
        [string]
        $suser,

        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage = 'A custom raw string parameter allowing inclusion of one or more custom extensions. Use only when no reasonable mapping exists to existing key names (type=string)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CustomExtensionRawString,

        #----------------------------custom label extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "c6a1" key. Recommended value is "Device IPv6 Address" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomIPv6Address1Label")]
        [string]
        $c6a1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "c6a2" key. Recommended value is "Source IPv6 Address" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomIPv6Address2Label")]
        [string]
        $c6a2Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "c6a3" key. Recommended value is "Destination IPv6 Address" (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomIPv6Address3Label")]
        [string]
        $c6a3Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "c6a4" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomIPv6Address4Label")]
        [string]
        $c6a4Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cfp1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomFloatingPoint1Label")]
        [string]
        $cfp1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cfp2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomFloatingPoint2Label")]
        [string]
        $cfp2Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cfp3" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomFloatingPoint3Label")]
        [string]
        $cfp3Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cfp4" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomFloatingPoint4Label")]
        [string]
        $cfp4Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cn1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomNumber1Label")]
        [string]
        $cn1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cn2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomNumber2Label")]
        [string]
        $cn2Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cn3" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomNumber3Label")]
        [string]
        $cn3Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cs1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomString1Label")]
        [string]
        $cs1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cs2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomString2Label")]
        [string]
        $cs2Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cs3" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomString3Label")]
        [string]
        $cs3Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cs4" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomString4Label")]
        [string]
        $cs4Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cs5" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomString5Label")]
        [string]
        $cs5Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "cs6" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [Alias("deviceCustomString6Label")]
        [string]
        $cs6Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "deviceCustomDate1" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $deviceCustomDate1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "deviceCustomDate2" key (type=string; max length=1023)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 1023)]
        [string]
        $deviceCustomDate2Label,

        #----------------------------flex label extensions----------------------------

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "flexDate1" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $flexDate1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "flexNumber1" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $flexNumber1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "flexNumber2" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $flexNumber2Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "flexString1" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $flexString1Label,

        [Parameter(ParameterSetName = 'CEFExtensionFields', ValueFromPipelineByPropertyName=$true, HelpMessage = 'Label name for the "flexString2" key (type=string; max length=128)')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(0, 128)]
        [string]
        $flexString2Label
    )
    Begin {
        [String]$CEFVersion = 'CEF:0'
        Write-Verbose "New-CEFMessage: CEF version being used: $CEFVersion"
    }

    Process {
        [String]$CEFExtension = ''

        Write-Verbose "New-CEFMessage: Convert MAC addresses to CEF expected format"
        If ($dmac) {$dmac = Format-MacAddress -MacAddress $dmac -Separator ':' -Case Upper}
        If ($dvcmac) {$dvcmac = Format-MacAddress -MacAddress $dvcmac -Separator ':' -Case Upper}
        If ($smac) {$smac = Format-MacAddress -MacAddress $smac   -Separator ':' -Case Upper}

        Write-Verbose "New-CEFMessage: Loop through the list of specified params"
        ($PSCmdlet.MyInvocation.BoundParameters).Keys | ForEach-Object {
            Write-Verbose "New-CEFMessage: Get handle for parameter $_ before entering another ForEach-Object loop block"
            $i = $_

            Write-Verbose "New-CEFMessage: Loop through the param sets of which param $_ is a member"
            (($MyInvocation.MyCommand.Parameters.Item($i)).ParameterSets).Keys | ForEach-Object {

                Write-Verbose "New-CEFMessage: Check if param $i is a member of param set 'CEFExtensionFields'"
                If ($_ -ccontains 'CEFExtensionFields') {

                    Write-Verbose "New-CEFMessage: Param $i is a member of param set 'CEFExtensionFields'"
                    If (($MyInvocation.MyCommand.Parameters.Item($i)).ParameterType -eq [CEF_Ext_Device_Direction]) {
                        Write-Verbose "New-CEFMessage: Adding the value for $i as an [int] to the CEF extension"
                        $CEFExtension += (((Get-Variable $i).Name), ((Get-Variable $i).Value -as [int]) -join '=') + ' '
                    }
                    ElseIf (($MyInvocation.MyCommand.Parameters.Item($i)).ParameterType -eq [CEF_Ext_Event_Type]) {
                        Write-Verbose "New-CEFMessage: Adding the value for $i as an [int] to the CEF extension"
                        $CEFExtension += (((Get-Variable $i).Name), ((Get-Variable $i).Value -as [int]) -join '=') + ' '
                    }
                    Else {
                        Write-Verbose "New-CEFMessage: Adding the value for $i to the CEF extension"
                        $CEFExtension += (((Get-Variable $i).Name), ((Get-Variable $i).Value) -join '=') + ' '
                    }
                }
            }
        }

        Write-Verbose "New-CEFMessage: Add raw, non-standard CEF extension fields directly (this param is not a member of the 'CEFExtensionFields' paramset on purpose, we handle it uniquely because it contains both key names and values, e.g.- 'cefkeyname=value')"
        If ($CustomExtensionRawString) {
            $CEFExtension += $CustomExtensionRawString
            Write-Verbose "New-CEFMessage: CEF custom extension fields being used: $CEFExtension"
        }

        Write-Verbose "New-CEFMessage: Trim trailing space from CEF extension, if there are any"
        $CEFExtension = $CEFExtension.ToString().TrimEnd(' ')

        Write-Verbose "New-CEFMessage: CEF extension being used: $CEFExtension"

        [String]$CEFHeader = "$CEFVersion|$DeviceVendor|$DeviceProduct|$DeviceVersion|$DeviceEventClassId|$Name|$Severity|"

        If ($CEFExtension -ne '') {
            Write-Verbose "New-CEFMessage: Assemble CEF header and extension into CEF message"
            $CEFMessage = '{0}{1}' -f $CEFHeader, $CEFExtension
        }
        Else {
            Write-Verbose "New-CEFMessage: No CEF extensions were used, CEF header only will be the CEF message"
            $CEFMessage = $CEFHeader
        }

        Write-Output $CEFMessage
    }

    End {}
}

# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
Export-ModuleMember -Function New-CEFMessage