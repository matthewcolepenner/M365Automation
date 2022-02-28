<#
.SYNOPSIS
    Script to automate the various assignments and changes of Teams phone numbers, and make the associated Active Directory updates
.NOTES
    author: Matthew Penner
    date:   Feb 22, 2022
#>
 
function Test-TelephoneNumberIsFreeInAD {
    # Returns $true if telephone number is free in AD
 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\+1\d{10}$')]
        [string]
        $TelephoneNumberPlus
        )
    
        if (Get-ADUser -Filter {TelephoneNumber -eq $TelephoneNumberPlus} -SearchBase $Domain -Properties TelephoneNumber) {
        Write-Host "$TelephoneNumberPlus is already in use in the domain"
        return $false
    } else {
        Write-Host "$TelephoneNumberPlus is free for use in the domain"
        return $true
    }
}
 
function Test-TelephoneNumberIsFreeInTeams {
    # Returns $true if telephone number is free in Teams
   
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^1\d{10}$')]
        [string]
        $TelephoneNumberNoPlus
        )
 
    if (Get-CsOnlineTelephoneNumber -TelephoneNumber $TelephoneNumberNoPlus -IsNotAssigned -WarningAction SilentlyContinue) {
        Write-Host "$TelephoneNumberNoPlus is free for use in Teams"
        return $True
    } else {
        Write-Host "$TelephoneNumberNoPlus is already in use in Teams"
        return $False
    }
}
 
function Convert-TelephoneNumberNoPlusToTelephoneNumberPlus {
    # Converts 1XXXXXXXXXX to +1XXXXXXXXXX
   
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^1\d{10}$')]
        [string]
        $TelephoneNumberNoPlus
        )
 
    $TelephoneNumberPlus = '+' + $TelephoneNumberNoPlus
 
    return $TelephoneNumberPlus
}
 
function Convert-TelephoneNumberPlusToTelephoneNumberNoPlus {
    # Converts +1XXXXXXXXXX to 1XXXXXXXXXX
   
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\+1\d{10}$')]
        [string]
        $TelephoneNumberPlus
        )
 
    $TelephoneNumberNoPlus = $TelephoneNumberPlus.TrimStart("+")
 
    return $TelephoneNumberNoPlus
}
 
function Confirm-PSTNLicensing {
    # Checks if user has PSTN licensing, and if not adds the user to the group
 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SamAccountName
    )
 
    if (-not $(Get-AdGroupMember -Identity $TeamsPSTNLicensingGroup -Recursive | ? {$_.SamAccountName -eq $SamAccountName})) {
        Write-Host "`n$SamAccountName is not licensed for PSTN calling. Adding to the $TeamsPSTNLicensingGroup group.`n"
        Add-ADGroupMember -Identity $TeamsPSTNLicensingGroup -Members $SamAccountName -Credential $AdminCredential -Confirm
    } else {
        Write-Host "`n$SamAccountName is licensed for PSTN calling, as they are in the $TeamsPSTNLicensingGroup group."
    }
 
}
 
function Set-TeamsTelephoneNumber {
    # Takes user and number, prompts for emergency location, and assigns in Teams
 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SamAccountName,
 
        [Parameter(Mandatory)]
        [string]
        $TelephoneNumberNoPlus
    )
 
    # Finds all Teams Emergency Locations, asks the user to select one, and returns the Location ID in the $LocationID variable
    $LocationID = $(Get-CsOnlineLisCivicAddress | Select-Object CompanyName,Description,HouseNumber,StreetName,PostalCode,StateOrProvince,CountryOrRegion,DefaultLocationID | Sort-Object CompanyName | Out-GridView -PassThru).DefaultLocationID.Guid
 
    "Setting $SamAccountName Teams phone number to $TelephoneNumberNoPlus"
    "Setting $SamAccountName Teams location ID to $LocationID"
    Set-CsOnlineVoiceUser -Identity $SamAccountName -TelephoneNumber $TelephoneNumberNoPlus -LocationID $LocationID
 
}
 
function Set-ADCallSettings {
    # Sets the required call settings for the user in Active Directory
 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SamAccountName
    )
 
    $EmailAddress = $(Get-ADUser $SamAccountName -Properties EmailAddress).EmailAddress
    $SIP = SIP:$EmailAddress
 
    "Setting MSRTC AD call settings for $SamAccountName"
 
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-DeploymentLocator" = "sipfed.online.lync.com"}
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-FederationEnabled"=$True}
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-InternetAccessEnabled"=$True}
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-OptionFlags"="385"}
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-UserEnabled"=$true}
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-UserPolicies"="21=1"}  
    Set-ADUser -Credential $AdminCredential $SamAccountName -add @{"msRTCSIP-UserPolicies"="27=1"}
    Set-ADUser -Credential $AdminCredential $SamAccountName -add @{"msRTCSIP-UserPolicies"="7=6"}
    Set-ADUser -Credential $AdminCredential $SamAccountName -add @{"msRTCSIP-UserPolicies"="9=2"}
    Set-ADUser -Credential $AdminCredential $SamAccountName -Replace @{"msRTCSIP-PrimaryUserAddress"="$SIP"}
    Set-ADUser -Credential $AdminCredential $SamAccountName -add @{proxyAddresses="$SIP"}
}
 
function Write-UserTelephoneSettings {
    # For before and after changes; writes the current user telephone settings, and asks to copy them to the clipboard
   
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SamAccountName
    )
 
    $UserTelephoneSettings = [PSCustomObject]@{
        SamAccountName =                $(Get-ADUser $SamAccountName -Properties SamAccountName -ErrorAction SilentlyContinue).SamAccountName
        EmailAddress =                  $(Get-ADUser $SamAccountName -Properties EmailAddress -ErrorAction SilentlyContinue).EmailAddress
        ADTelephoneNumber =             $(Get-ADUser $SamAccountName -Properties TelephoneNumber -ErrorAction SilentlyContinue).TelephoneNumber
        TeamsTelephoneNumber =          $(try { $(Get-CsOnlineUser $SamAccountName -ErrorAction SilentlyContinue).LineURI.TrimStart(tel:) } catch { $null })
        TeamsLocationID =               $(Get-CsOnlineVoiceUser -Identity $SamAccountName -ExpandLocation -ErrorAction SilentlyContinue).Location.LocationID.Guid
        TeamsLocationName =             $(Get-CsOnlineVoiceUser -Identity $SamAccountName -ExpandLocation -ErrorAction SilentlyContinue).Location.CompanyName
        TeamsLocationDescription =      $(Get-CsOnlineVoiceUser -Identity $SamAccountName -ExpandLocation -ErrorAction SilentlyContinue).Location.Description
        ADLocation =                    $(Get-ADUser $SamAccountName -Properties Office -ErrorAction SilentlyContinue).Office
        ADCallSettingsConfigured =      $( if ($(Get-ADUser -Identity $SamAccountName -Properties * -ErrorAction SilentlyContinue).'msRTCSIP-UserEnabled' ) { $true } else { $false })
        TeamsPSTNLicensingConfigured =  $($(Get-ADPrincipalGroupMembership -Identity $SamAccountName -ErrorAction SilentlyContinue | Select-Object SamAccountName).SamAccountName -contains $TeamsPSTNLicensingGroup)
    }
 
    $UserTelephoneSettings | Format-List
 
    if ($(Read-Host -Prompt "Copy above to clipboard? [Y/n] ") -ne "n") {
        $UserTelephoneSettings | Format-List | Clip
        Write-Host "[ COPIED ]"
    } else {
        Write-Host "[ NOT COPIED ]"
    }
 
}
 
function Write-TeamsLocationInventory {
    # Writes all Teams emergency locations
   
    Get-CsOnlineLisCivicAddress | Select-Object CompanyName,Description,HouseNumber,StreetName,PostalCode,StateOrProvince,CountryOrRegion,DefaultLocationID,CivicAddressID | Sort-Object CompanyName | Format-Table -AutoSize
}
 
function Write-ADLocationInventory {
    # Writes all AD Office locations (likely to contain dirty information)
   
    $(Get-ADuser -Filter * -SearchBase $EmployeesOU -Properties Office | Group-Object Office | Sort-Object Name).Name
}
 
function Get-RecommendedTelephoneNumberPlus {
    # Returns the first free number for a user
   
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SamAccountName
    )
 
    $Office = $(Get-ADUser $SamAccountName -Properties Office | Select-Object Office).Office
 
    Write-Host "Searching for the next available telephone number at $Office"
 
    # Generates a list of the existing eight-digit prefixes for the $Office, sorted by most popular first
    $TelephonePrefixNoPlusArray = $($(Get-ADUser -Filter {Office -like $Office} -SearchBase $EmployeesOU -Properties TelephoneNumber | Select-Object @{Name='TelephoneNumberPrefix';Expression={$_.TelephoneNumber.substring(0,10)}} | Group-Object -Property TelephoneNumberPrefix | Sort-Object -property Count -Descending).Name | Where-Object {$_ -match '^\+1\d{8}$'}).TrimStart("+")
 
    foreach ($TelephonePrefixNoPlus in $TelephonePrefixNoPlusArray) {
       
        # For this eight-digit prefix, generate a list of all unassigned Teams numbers, and for each one...
        $TelephoneUnassignedTeamsNoPlusArray = $(Get-CsOnlineTelephoneNumber -TelephoneNumberStartsWith $TelephonePrefixNoPlus -isnotassigned | Select-Object Id).id
 
        foreach ($TelephoneUnassignedTeamsNoPlus in $TelephoneUnassignedTeamsNoPlusArray) {
           
            # If number is found unassigned in both Teams and AD, return it and stop the nested loop
            if ($(Test-TelephoneNumberIsFreeInAD -TelephoneNumberPlus $("+" + $TelephoneUnassignedTeamsNoPlus)) -eq $true) {
                $RecommendedTelephoneNumberPlus = "+" + $TelephoneUnassignedTeamsNoPlus
 
                $StopLoop = $true
                break
            }
        }
        if ($StopLoop) {break}
    }
 
    Write-Host "Found $RecommendedTelephoneNumberPlus at $Office"
 
    return $RecommendedTelephoneNumberPlus
}
 
#_______________________________________________________________________________________________________________#
# Connect to Microsoft Teams and get administrator credential
 
"Connecting to Microsoft Teams Powershell"
Connect-MicrosoftTeams | Out-Null
Write-Host "Enter administrator credentials:"
$AdminCredential = Get-Credential
 
$EmployeesOU = Read-Host "Enter DN of Employees OU:"
$Domain = Read-Host "Enter DN of the domain:"
$TeamsPSTNLicensingGroup = Read-Host "Enter name of Teams PSTN licensing group:"
 
# User selects one of these options to run a scripted action, or "Q" to quit
$ScriptedActions = @{
    "Q" = "QUIT"
    "Write AD Location Inventory" = "[AD] Write AD location inventory"
    "Assign PSTN Call Licensing Security Group" = "[AD] Assigns PSTN call licensing to a user ($TeamsPSTNLicensingGroup security group)"
    "Set User AD MSRTC Call Settings" = "[AD] Only needs to be run if accidentally missed"
    "Write Teams Location Inventory" = "[TEAMS] Includes all relevant fields; useful when assigning number in Teams Administration Centre"
    "Assign Specific Number to a User" = "[AD+TEAMS] Assigns in both AD and Teams"
    "Write Current User State" = "[AD+Teams] Recommended before changing any user settings"
    "Assign Recommended Number to a User" = "[AD+TEAMS] Recommended for new hires"
}
 
do {
    $Selection = $($ScriptedActions.GetEnumerator() | Sort-Object -Property Name | Out-GridView -PassThru).Name
    switch ($Selection) {
        "Write AD Location Inventory" {
 
            Write-ADLocationInventory
           
        } "Assign PSTN Call Licensing Security Group" {
 
            $SamAccountName = Read-Host "SamAccountName "
            Confirm-PSTNLicensing -SamAccountName $SamAccountName
           
        } "Set User AD MSRTC Call Settings" {
 
            $SamAccountName = Read-Host "SamAccountName "
            Set-ADCallSettings -SamAccountName $SamAccountName
           
        } "Write Teams Location Inventory" {
 
            Write-TeamsLocationInventory
 
        } "Assign Specific Number to a User" {
 
            $SamAccountName = Read-Host "SamAccountName "
            $TelephoneNumberNoPlus = Read-Host "TelephoneNumberNoPlus (1XXXXXXXXXX) "
            $TelephoneNumberPlus = Convert-TelephoneNumberNoPlusToTelephoneNumberPlus -TelephoneNumberNoPlus $TelephoneNumberNoPlus
           
            Write-Host "User settings before the change:"
            Write-UserTelephoneSettings -SamAccountName $SamAccountName
            Confirm-PSTNLicensing -SamAccountName $SamAccountName
            Set-ADCallSettings -SamAccountName $SamAccountName
            Set-TeamsTelephoneNumber -SamAccountName $SamAccountName -TelephoneNumberNoPlus -$TelephoneNumberNoPlus
            Set-ADUser -Credential $AdminCredential -Identity $SamAccountName -OfficePhone $TelephoneNumberPlus
            Start-Sleep -Seconds 10 # waiting for Admin Centre to update before writing user settings to avoid error
            Write-Host "User settings after the change:"
            Write-UserTelephoneSettings -SamAccountName $SamAccountName
 
        } "Write Current User State" {
 
            $SamAccountName = Read-Host "SamAccountName "
            Write-UserTelephoneSettings -SamAccountName $SamAccountName
 
        } "Assign Recommended Number to a User" {
 
            $SamAccountName = Read-Host "SamAccountName "
            $TelephoneNumberPlus = $(Get-RecommendedTelephoneNumberPlus -SamAccountName $SamAccountName)
            $TelephoneNumberNoPlus = Convert-TelephoneNumberPlusToTelephoneNumberNoPlus -TelephoneNumberPlus $TelephoneNumberPlus
 
            Write-Host "User settings before the change:"
            Write-UserTelephoneSettings -SamAccountName $SamAccountName
            Confirm-PSTNLicensing -SamAccountName $SamAccountName
            Set-ADCallSettings -SamAccountName $SamAccountName
            Set-TeamsTelephoneNumber -SamAccountName $SamAccountName -TelephoneNumberNoPlus -$TelephoneNumberNoPlus
            Set-ADUser -Credential $AdminCredential -Identity $SamAccountName -OfficePhone $TelephoneNumberPlus
            Start-Sleep -Seconds 10 # waiting for Admin Centre to update before writing user settings to avoid error
            Write-Host "User settings after the change:"
            Write-UserTelephoneSettings -SamAccountName $SamAccountName          
 
        }
    }
       
    if ($Selection -ne "Q") {Read-Host -Prompt "`nPress ENTER to run another scripted action"}
 
} until ($Selection -eq 'Q') # Quit
 
# Disconnect from Microsoft Teams to end the script
 
Write-Host "Disconnecting from Microsoft Teams"
Disconnect-MicrosoftTeams