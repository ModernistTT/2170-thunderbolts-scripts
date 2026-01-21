$msg = "
===============================================================================
Script Name:	-	Windows 10/11 Enterprise PS1 script
Team #		-	18-2170 Thunderbolts
Last Updated  	-	11/25/2025
Description 	-
			This script is designed to run automatically, however certain
			aspects will require user input to be configured.
===============================================================================

"



#-------------------------------------- CONSTANTS --------------------------------------#
# Users:
$DEFAULTUSERS = @("Administrator","Guest","DefaultAccount","defaultuser0","WDAGUtilityAccount")
$DEFAULTPASSWORD = "P@ssword123"
$SECUREPASSWORD = ConvertTo-SecureString $DEFAULTPASSWORD -AsPlainText -Force

# Policy:
$MINPWLEN = 12
$MAXPWAGE = 90
$MINPWAGE = 10
$PWHIST = 10



#-------------------------------------- BEGIN CONFIG --------------------------------------#
Write-Host $msg

Write-Host "Before executing the following script, please create a .txt file named 'users.txt', containing all of the AUTHORIZED users. You may also add authorized users who need to be added to the PC."
$path = Read-Host "Please enter the file path to users.txt (include the filename)"

while ([string]::IsNullOrWhitespace($path) -or -not (Test-Path $path)) {
	Write-Host "Invalid path. Please enter again."
	$path = Read-Host "Please enter the file path to users.txt (include the filename)"
}

$users = Get-Content -Path $path

# Look for each user in the database, ask to add them if they are not present
Write-Host "Verifying all authorized users are present..."
foreach ($line in $users) {
	$username = Get-LocalUser -Name $line -ErrorAction SilentlyContinue
	if (-not $username) {
		$answer = Read-Host "User '$line' not a current user. Would you like to add them? Y/N"
		$answer = $answer.toLower()

		switch ($answer) {
			"y" {
				try {
					New-LocalUser -Name $line -password $securepassword -Description "added by script"
					Add-LocalGroupMember -Group "Users" -Member $line
					Write-Host "User '$line' created."
				} catch {
					Write-Host "Failed to add user. Error: $_";
				}
				break
			}
			"n" {
				Write-Host "Not adding user."
				break
			}
			# TBA: Repeat the loop
			default {
				Write-Host "Please input a valid answer!"   
			}
		}
	}
}

# Scan the database of users, remove them if they are not AUTHORIZED
$localusers = Get-LocalUser
Write-Host "Verifying all users on the PC are authorized..."
foreach ($user in $localusers) {
	if ((-not($users -contains $user)) -and ($user.enabled -eq $true)) {
		$answer = Read-Host "User '$user' is not an authorized user, or is a default that is not disabled. Disable? Y/N"
		$answer = $answer.toLower()

		switch ($answer) {
			"y" {
				Disable-LocalUser -Name $user
				break
			}
			"n" {
				Write-Host "Not disabling user."
				break
			}
			# TBA: Repeat the loop
			default {
				Write-Host "Please input a valid answer!"
			}
		}
	}
}

# Verify Administrators
$answer = Read-Host "This script can verify Administrators. To do so, you will need a separate text file containing authorized Administrators. Would you like to proceed? Y/N"
$answer = $answer.toLower()

if ($answer -eq "y") {
	$path = Read-Host "Please enter the file path to your text file containing Administrators (include the filename) or type 'cancel' to cancel"
	
	while ((([string]::IsNullOrWhitespace($path)) -or (-not (Test-Path $path))) -and ($path -ne "cancel")) {
		Write-Host "Invalid path. Please enter again."
		$path = Read-Host "Please enter the file path  your text file containing Administrator (include the filename)"
	}
	
	if ($path -eq ("cancel")) {
		break
	}
	
	$administrators = Get-Content -Path $path
	$localadministrators = Get-LocalGroupMember -Group "Administrators" | ForEach-Object { 
		($_).Name -split '\\' | Select-Object -Last 1
	}
	
	Write-Host "Verifying all authorized Administrators have privileges..."
	foreach ($line in $administrators) {
		if ($line -notin $localadministrators) {
			$answer = Read-Host "User '$line' does not have privileges. Would you like to add them? Y/N"
			$answer = $answer.toLower()
			
			switch ($answer) {
				"y" {
					Add-LocalGroupMember -Group "Administrators" -Member $line
					break
				}
				"n" {
					Write-Host "Not adding privileges for user."
					break
				}
				# TBA: Repeat the loop
				default {
					Write-Host "Please input a valid answer!"
				}
			}
		}
	}
	
	$defaultadministrators = @("Administrator")
	Write-Host "Verifying all Administrators on the PC are authorized..."
	foreach ($admin in $localadministrators) {		
		if (-not($administrators -contains $admin) | Where-Object {$admin -notin $defaultadministrators} ) {
			$answer = Read-Host "User '$admin' is not an authorized Administrator. Remove? Y/N"
			$answer = $answer.toLower()

			switch ($answer) {
				"y" {
					Remove-LocalGroupMember -Group "Administrators" -Member $admin
					break
				}
				"n" {
					Write-Host "Not removing user."
					break
				}
				# TBA: Repeat the loop
				default {
					Write-Host "Please input a valid answer!"
				}
			}
		}
	}
}

# Check for passwords
# TBA 

# Security Policies
function Set-PasswordPolicy {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MinimumPasswordLength" -Value $MINPWLEN
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaximumPasswordAge" -Value $MAXPWAGE
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MinimumPasswordAge" -Value $MINPWAGE
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordHistorySize" -Value $PWHIST
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordHistorySize" -Value $PWHIST
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ClearTextPassword" -Value 0
	Write-Host "Password policy configured successfully."
}
Set-PasswordPolicy

# Audit Policies 
function Set-AuditPolicy {
	secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    $content = Get-Content "$env:TEMP\secpol.cfg"
    
    # Modify audit settings (0=None, 1=Success, 2=Failure, 3=Both)
    $content = $content -replace "AuditAccountLogon = .*", "AuditAccountLogon = 3"
    $content = $content -replace "AuditAccountManage = .*", "AuditAccountManage = 3"
    $content = $content -replace "AuditDSAccess = .*", "AuditDSAccess = 3"
    $content = $content -replace "AuditLogonEvents = .*", "AuditLogonEvents = 3"
    $content = $content -replace "AuditObjectAccess = .*", "AuditObjectAccess = 3"
    $content = $content -replace "AuditPolicyChange = .*", "AuditPolicyChange = 3"
    $content = $content -replace "AuditPrivilegeUse = .*", "AuditPrivilegeUse = 3"
    $content = $content -replace "AuditProcessTracking = .*", "AuditProcessTracking = 3"
    $content = $content -replace "AuditSystemEvents = .*", "AuditSystemEvents = 3"
    
    $content | Set-Content "$env:TEMP\secpol_modified.cfg"
    secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol_modified.cfg" /areas SECURITYPOLICY | Out-Null
    
    Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secpol_modified.cfg" -ErrorAction SilentlyContinue
	
	auditpol /set /category:"*" /success:enable | Out-Null
	auditpol /set /category:"*" /failure:enable | Out-Null
	
	Write-Host "Audit policy configured successfully."
}
Set-AuditPolicy

function Set-FirewallPolicy {
    # Get firewall status for all profiles
    $domainProfile = (Get-NetFirewallProfile -Name Domain).Enabled
    $privateProfile = (Get-NetFirewallProfile -Name Private).Enabled
    $publicProfile = (Get-NetFirewallProfile -Name Public).Enabled
    
    Write-Host "Domain Profile: $(if($domainProfile){'Enabled'}else{'Disabled'})"
    Write-Host "Private Profile: $(if($privateProfile){'Enabled'}else{'Disabled'})"
    Write-Host "Public Profile: $(if($publicProfile){'Enabled'}else{'Disabled'})"
    
    # Check if any profile is disabled
    if (-not $domainProfile -or -not $privateProfile -or -not $publicProfile) {
        $answer = Read-Host "`nOne or more firewall profiles are disabled. Enable all profiles? Y/N"
        $answer = $answer.ToLower()
        
        switch ($answer) {
            "y" {
                try {
                    # Enable firewall for all profiles
                    netsh advfirewall set allprofiles state on | Out-Null
                    
                    # Ensure Windows Firewall service is running
                    $service = Get-Service -Name "mpssvc" -ErrorAction SilentlyContinue
                    if ($service.Status -ne "Running") {
                        Write-Host "Starting Windows Firewall service..."
                        sc.exe config mpssvc start= auto | Out-Null
                        net start mpssvc | Out-Null
                    }
                    
                    Write-Host "Firewall enabled successfully for all profiles."
                } catch {
                    Write-Host "Failed to enable firewall. Error: $_"
                }
                break
            }
            "n" {
                Write-Host "Firewall will remain in current state."
                break
            }
            default {
                Write-Host "Please input a valid answer!"
            }
        }
    } else {
        Write-Host "`nAll firewall profiles are already enabled."
    }
    
    # Verify Windows Firewall service status
    $service = Get-Service -Name "mpssvc" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Windows Firewall Service Status: $($service.Status)"
        Write-Host "Windows Firewall Service Startup Type: $($service.StartType)"
    }
}
Set-FirewallPolicy
