function Get-NormalizedNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OldNumber
    )
 
    # Checks every value in $OldNumber and concats digits to $NewNumber
    for ($index = 0 ; $index -le $OldNumber.Length ; $index++) {
        if ($OldNumber[$index] -match '\d') {
            $NewNumber += $OldNumber[$index]
        }
    }
 
    # If the starting number of NewNumber isn't 1 or 9, adds 1 at the front
    if (($NewNumber[0] -notmatch '1') -and ($NewNumber[0] -notmatch '9')) {
        $NewNumber = '1'+$NewNumber
    }
 
    # Adds + character to the start
    $NewNumber = '+'+$NewNumber
 
    return $NewNumber
}
 
$OU = Read-Host "Enter DN of Employees OU:"

$Users = $(Get-ADUser -Filter * -SearchBase $OU -Properties mobile,SamAccountName | Where-Object {($_.mobile -notmatch '\+1\d{10}') -and ($_.mobile -match '\d') -and ($_.mobile -notmatch 'x')} | Select-Object SamAccountName,mobile)
 
$UsersToChange = @()
 
foreach ($User in $Users) {
    $UsersToChange += [PSCustomObject]@{SamAccountName=$User.SamAccountName;mobile=$User.mobile;NormalizedMobile=$(Get-NormalizedNumber -OldNumber $User.mobile)}
}
 
foreach ($UserToChange in $UsersToChange) {
   
    $SamAccountName = $UserToChange.SamAccountName
    $mobile = $UserToChange.mobile
    $NormalizedMobile = $UserToChange.NormalizedMobile
   
    $Confirmation = Read-Host "`nConfirm $SamAccountName from $mobile to $NormalizedMobile (y/N) "
 
    if ($Confirmation -eq "y") {
        Write-Host "Changing $SamAccountName from $mobile to $NormalizedMobile"
        Set-ADUser -identity $SamAccountName -MobilePhone $NormalizedMobile
        Write-Host "$SamAccountName confirmed change to $($(Get-ADUser $SamAccountName -Properties mobile).mobile)"
    } else {
        Write-Host "Confirmation denied"
    }
}