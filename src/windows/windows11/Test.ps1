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

try {
	$users = Get-Content -Path $path
} catch {
	Write-Host "Failed to read users file. Error: $_"
	exit
}

function Configure-Users {	
	# Look for each user in the database, ask to add them if they are not present
	Write-Host "Verifying all authorized users are present..."
	foreach ($line in $users) {
		$username = Get-LocalUser -Name $line -ErrorAction SilentlyContinue
		if (-not $username) {
			do {
				$answer = Read-Host "User '$line' not a current user. Would you like to add them? Y/N"
				$answer = $answer.toLower()
	
				switch ($answer) {
					"y" {
						try {
							New-LocalUser -Name $line -password $securepassword -Description "added by script"
							Add-LocalGroupMember -Group "Users" -Member $line
							Write-Host "User '$line' created."
						} catch {
							Write-Host "Failed to add user. Error: $_"
						}
						break
					}
					"n" {
						break
					}
					default {
						Write-Host "Please input a valid answer (Y/N)!"
						$answer = $null
					}
				}
			} while ($answer -ne "y" -and $answer -ne "n")
		}
	}
	
	# Scan the database of users, remove them if they are not authorized
	try {
		$localusers = Get-LocalUser
	} catch {
		Write-Host "Failed to retrieve local users. Error: $_"
		exit
	}
	
	Write-Host "Verifying all users on the PC are authorized..."
	foreach ($user in $localusers) {
		if ((-not($users -contains $user.Name)) -and ($user.enabled -eq $true) -and ($user.Name -notin $DEFAULTUSERS)) {
			do {
				$answer = Read-Host "User '$($user.Name)' is not an authorized user. Disable? Y/N"
				$answer = $answer.toLower()
	
				switch ($answer) {
					"y" {
						try {
							Disable-LocalUser -Name $user.Name
							Write-Host "User '$($user.Name)' disabled."
						} catch {
							Write-Host "Failed to disable user. Error: $_"
						}
						break
					}
					"n" {
						break
					}
					default {
						Write-Host "Please input a valid answer (Y/N)!"
						$answer = $null
					}
				}
			} while ($answer -ne "y" -and $answer -ne "n")
		}
	}
	
	# Check and disable default accounts
	Write-Host "`nChecking default accounts..."
	foreach ($defaultUser in $DEFAULTUSERS) {
		$user = Get-LocalUser -Name $defaultUser -ErrorAction SilentlyContinue
		if ($user -and $user.Enabled) {
			Write-Host "Default account '$defaultUser' is enabled. Disabling..."
			try {
				Disable-LocalUser -Name $defaultUser
				Write-Host "Default account '$defaultUser' disabled."
			} catch {
				Write-Host "Failed to disable default account '$defaultUser'. Error: $_"
			}
		}
	}
	Write-Host "Ending user management."
}
Configure-Users

function Configure-Administrators {
	# Verify Administrators
	do {
		$answer = Read-Host "`nThis script can verify Administrators. To do so, you will need a separate text file containing authorized Administrators. Would you like to proceed? Y/N"
		$answer = $answer.toLower()
		
		if ($answer -ne "y" -and $answer -ne "n") {
			Write-Host "Please input a valid answer (Y/N)!"
		}
	} while ($answer -ne "y" -and $answer -ne "n")
	
	if ($answer -eq "y") {
		$path = Read-Host "Please enter the file path to your text file containing Administrators (include the filename) or type 'cancel' to cancel"
		
		while ((([string]::IsNullOrWhitespace($path)) -or (-not (Test-Path $path))) -and ($path -ne "cancel")) {
			Write-Host "Invalid path. Please enter again."
			$path = Read-Host "Please enter the file path your text file containing Administrator (include the filename) or type 'cancel' to cancel"
		}

		if ($path -ne "cancel") {
			try {
				secedit /export /cfg "$env:TEMP\secpol_check.cfg" /quiet | Out-Null
				$administrators = Get-Content -Path $path
				$localadministrators = Get-LocalGroupMember -Group "Administrators" | ForEach-Object { 
					($_).Name -split '\\' | Select-Object -Last 1
				}
			
				if (Test-Path "$env:TEMP\secpol_check.cfg") {
					$content = Get-Content "$env:TEMP\secpol_check.cfg"
					$adminNameLine = $content | Where-Object { $_ -match "NewAdministratorName" }
			
					if ($adminNameLine -and $adminNameLine -match 'NewAdministratorName\s*=\s*"(.+)"') {
						$currentAdminName = $matches[1]
			
						if ($currentAdminName -ne "Administrator") {
							Write-Host "WARNING - The built-in Administrator account has been renamed to '$currentAdminName'"
							do {
								$answer = Read-Host "Would you like to rename it back to 'Administrator'? Y/N"
								$answer = $answer.ToLower()
								
								if ($answer -ne "y" -and $answer -ne "n") {
									Write-Host "Please input a valid answer (Y/N)!"
								}
							} while ($answer -ne "y" -and $answer -ne "n")
							
							if ($answer -eq "y") {
								try {
									Rename-LocalUser -Name $currentAdminName -NewName "Administrator"
									Write-Host "Administrator account renamed successfully."
									$DEFAULTUSERS = @("Administrator","Guest","DefaultAccount","defaultuser0","WDAGUtilityAccount")
								} catch {
									Write-Host "Failed to rename Administrator account. Error: $_"
									Write-Host "Updating default users list to use '$currentAdminName' instead."
									$DEFAULTUSERS = @($currentAdminName,"Guest","DefaultAccount","defaultuser0","WDAGUtilityAccount")
								}
							} else {
								Write-Host "Administrator account will remain as '$currentAdminName'."
								Write-Host "Updating checks to use '$currentAdminName' instead of 'Administrator'."
								$DEFAULTUSERS = @($currentAdminName,"Guest","DefaultAccount","defaultuser0","WDAGUtilityAccount")
							}
						}
					}
					Remove-Item "$env:TEMP\secpol_check.cfg" -ErrorAction SilentlyContinue
				}
			} catch {
				Write-Host "WARNING - Could not check Administrator account name!"
			}
			
			if ($administrators -and $localadministrators) {
				Write-Host "Verifying all authorized Administrators have privileges..."
				foreach ($line in $administrators) {
					if ($line -notin $localadministrators) {
						do {
							$answer = Read-Host "User '$line' does not have privileges. Would you like to add them? Y/N"
							$answer = $answer.toLower()
							
							switch ($answer) {
								"y" {
									try {
										Add-LocalGroupMember -Group "Administrators" -Member $line
										Write-Host "User '$line' added to Administrators."
									} catch {
										Write-Host "Failed to add administrator privileges. Error: $_"
									}
									break
								}
								"n" {
									Write-Host "Not adding privileges for user."
									break
								}
								default {
									Write-Host "Please input a valid answer (Y/N)!"
									$answer = $null
								}
							}
						} while ($answer -ne "y" -and $answer -ne "n")
					}
				}
				
				Write-Host "Verifying all Administrators on the PC are authorized..."
				foreach ($admin in $localadministrators) {		
					if (-not($administrators -contains $admin) -and ($admin -notin $DEFAULTUSERS)) {
						do {
							$answer = Read-Host "User '$admin' is not an authorized Administrator. Remove? Y/N"
							$answer = $answer.toLower()
	
							switch ($answer) {
								"y" {
									try {
										Remove-LocalGroupMember -Group "Administrators" -Member $admin
										Write-Host "User '$admin' removed from Administrators."
									} catch {
										Write-Host "Failed to remove administrator privileges. Error: $_"
									}
									break
								}
								"n" {
									Write-Host "Not removing user."
									break
								}
								default {
									Write-Host "Please input a valid answer (Y/N)!"
									$answer = $null
								}
							}
						} while ($answer -ne "y" -and $answer -ne "n")
					}
				}
			}
		}
	}
	Write_host "Administrator configuration complete."
}
Configure-Administrators

function Set-FirewallPolicy {
	try {
		Write-Host "`nChecking firewall status..."
		
		# Get firewall status for all profiles
		$domainProfile = (Get-NetFirewallProfile -Name Domain).Enabled
		$privateProfile = (Get-NetFirewallProfile -Name Private).Enabled
		$publicProfile = (Get-NetFirewallProfile -Name Public).Enabled
		
		# Check if any profile is disabled
		if (-not $domainProfile -or -not $privateProfile -or -not $publicProfile) {
			do {
				$answer = Read-Host "One or more firewall profiles are disabled. Enable all profiles? Y/N"
				$answer = $answer.ToLower()
				
				if ($answer -ne "y" -and $answer -ne "n") {
					Write-Host "Please input a valid answer (Y/N)!"
				}
			} while ($answer -ne "y" -and $answer -ne "n")
			
			if ($answer -eq "y") {
				try {
					# Configure Windows Firewall service to start automatically
					Write-Host "Configuring Windows Firewall service..."
					sc.exe config mpssvc start= auto | Out-Null
					
					if ($LASTEXITCODE -ne 0) {
						throw "Failed to configure firewall service"
					}
					
					# Start the service if not running
					$service = Get-Service -Name "mpssvc" -ErrorAction SilentlyContinue
					if ($service.Status -ne "Running") {
						Write-Host "Starting Windows Firewall service..."
						Start-Service -Name "mpssvc" -ErrorAction Stop
					}
					
					# Enable firewall for all profiles
					netsh advfirewall set allprofiles state on | Out-Null
					
					if ($LASTEXITCODE -ne 0) {
						throw "Failed to enable firewall profiles"
					}
					
					Write-Host "Firewall enabled successfully for all profiles."
				} catch {
					Write-Host "Failed to enable firewall. Error: $_"
				}
			} else {
				Write-Host "Firewall will remain in current state."
			}
		} else {
			Write-Host "All firewall profiles are already enabled."
			
			try {
				# Still ensure service is configured properly
				sc.exe config mpssvc start= auto | Out-Null
				$service = Get-Service -Name "mpssvc" -ErrorAction SilentlyContinue
				if ($service -and $service.Status -ne "Running") {
					Start-Service -Name "mpssvc" -ErrorAction Stop
				}
			} catch {
				Write-Host "Failed to configure firewall service. Error: $_"
			}
		}
	} catch {
		Write-Host "Failed to check firewall status. Error: $_"
	}
}
Set-FirewallPolicy

function Set-PasswordPolicy {
	try {
		Write-Host "`nConfiguring password policy..."
		
		# Configure length, age, and history
		net accounts /minpwlen:$MINPWLEN | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set minimum password length" }
		net accounts /maxpwage:$MAXPWAGE | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set maximum password age" }
		net accounts /minpwage:$MINPWAGE | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set minimum password age" }
		net accounts /uniquepw:$PWHIST | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set password history" }

		# Configure settings with secedit
		secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet | Out-Null
		if (-not (Test-Path "$env:TEMP\secpol.cfg")) {
			throw "Failed to export security policy"
		}

		$content = Get-Content "$env:TEMP\secpol.cfg"
		$content = $content -replace "PasswordComplexity = .*", "PasswordComplexity = 1"
		$content = $content -replace "ClearTextPassword = .*", "ClearTextPassword = 0"
		$content | Set-Content "$env:TEMP\secpol_modified.cfg"

		secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol_modified.cfg" /areas SECURITYPOLICY /quiet | Out-Null
		Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
		Remove-Item "$env:TEMP\secpol_modified.cfg" -ErrorAction SilentlyContinue
			
		Write-Host "Password policy configured successfully."
	} catch {
		Write-Host "Failed to configure password policy. Error: $_"
		Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
		Remove-Item "$env:TEMP\secpol_modified.cfg" -ErrorAction SilentlyContinue
	}
}
Set-PasswordPolicy

# Lockout Policies
function Set-LockoutPolicy {
	try {
		Write-Host "`nConfiguring account lockout policy..."
		
		net accounts /lockoutthreshold:10 | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set lockout threshold" }
		
		net accounts /lockoutduration:30 | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set lockout duration" }
		
		net accounts /lockoutwindow:30 | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to set lockout window" }
		
		Write-Host "Account lockout policy configured successfully."
	} catch {
		Write-Host "Failed to configure account lockout policy. Error: $_"
	}
}
Set-LockoutPolicy

# Audit Policies 
function Set-AuditPolicy {
	try {
		Write-Host "`nConfiguring audit policy..."
		
		secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet | Out-Null
		
		if (-not (Test-Path "$env:TEMP\secpol.cfg")) {
			throw "Failed to export security policy"
		}
		
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
		secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol_modified.cfg" /areas SECURITYPOLICY /quiet | Out-Null
		
		Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
		Remove-Item "$env:TEMP\secpol_modified.cfg" -ErrorAction SilentlyContinue
		
		auditpol /set /category:"*" /success:enable | Out-Null
		auditpol /set /category:"*" /failure:enable | Out-Null
		
		Write-Host "Audit policy configured successfully."
	} catch {
		Write-Host "Failed to configure audit policy. Error: $_"
		Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
		Remove-Item "$env:TEMP\secpol_modified.cfg" -ErrorAction SilentlyContinue
	}
}
Set-AuditPolicy

# Check User Rights
function Check-UserRightsAssignment {
	try {
		Write-Host "`nScanning User Rights Assignments for security issues..."
		
		secedit /export /cfg "$env:TEMP\secpol_rights.cfg" /quiet | Out-Null
		
		if (-not (Test-Path "$env:TEMP\secpol_rights.cfg")) {
			throw "Failed to export security policy"
		}
		
		$content = Get-Content "$env:TEMP\secpol_rights.cfg"
		
		# List of sensitive rights
		$sensitiveRights = @{
			"SeDebugPrivilege" = "Debug programs"
			"SeTakeOwnershipPrivilege" = "Take ownership of files or other objects"
			"SeLoadDriverPrivilege" = "Load and unload device drivers"
			"SeBackupPrivilege" = "Back up files and directories"
			"SeRestorePrivilege" = "Restore files and directories"
			"SeSecurityPrivilege" = "Manage auditing and security log"
			"SeSystemEnvironmentPrivilege" = "Modify firmware environment values"
			"SeImpersonatePrivilege" = "Impersonate a client after authentication"
			"SeCreateTokenPrivilege" = "Create a token object"
			"SeTcbPrivilege" = "Act as part of the operating system"
			"SeShutdownPrivilege" = "Shut down the system"
			"SeRemoteShutdownPrivilege" = "Force shutdown from a remote system"
			"SeInteractiveLogonRight" = "Allow log on locally"
			"SeNetworkLogonRight" = "Access this computer from the network"
			"SeRemoteInteractiveLogonRight" = "Allow log on through Remote Desktop Services"
			"SeBatchLogonRight" = "Log on as a batch job"
			"SeServiceLogonRight" = "Log on as a service"
		}
		
		# Standard groups that are typically safe (built-in groups)
		$safeGroups = @(
			"*S-1-5-32-544",  # Administrators
			"*S-1-5-32-545",  # Users
			"*S-1-5-32-546",  # Guests
			"*S-1-5-32-547",  # Power Users
			"*S-1-5-32-551",  # Backup Operators
			"*S-1-5-32-568",  # IIS_IUSRS
			"*S-1-5-11",       # Authenticated Users
			"*S-1-5-19",       # Local Service
			"*S-1-5-20",       # Network Service
			"*S-1-5-6",        # Service
			"*S-1-1-0",        # Everyone
			"*S-1-5-4"         # Interactive
		)
		
		$issues = @()
		$inPrivilegeSection = $false
		$modificationsNeeded = $false

		foreach ($line in $content) {
			if ($line -match "^\[Privilege Rights\]") {
				$inPrivilegeSection = $true
				continue
			}

			if ($line -match "^\[.*\]" -and $line -notmatch "^\[Privilege Rights\]") {
				$inPrivilegeSection = $false
			}

			if ($inPrivilegeSection -and $line -match "^(\w+)\s*=\s*(.+)") {
				$rightName = $matches[1]
				$assignedTo = $matches[2]

				if ($sensitiveRights.ContainsKey($rightName)) {
					$accounts = $assignedTo -split ','
					
					foreach ($account in $accounts) {
						$account = $account.Trim()
						
						# Check if it's a SID (starts with *S-1-)
						if ($account -match '^\*S-1-') {
							# Check if it's NOT a standard safe group SID
							$isSafeGroup = $false
							foreach ($safeGroup in $safeGroups) {
								if ($account -like $safeGroup) {
									$isSafeGroup = $true
									break
								}
							}
							
							if (-not $isSafeGroup) {
								# Try to resolve the SID to a name
								try {
									$sid = $account.TrimStart('*')
									$objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
									$objUser = $objSID.Translate([System.Security.Principal.NTAccount])
									$accountName = $objUser.Value
									
									$issues += [PSCustomObject]@{
										Right = $sensitiveRights[$rightName]
										RightName = $rightName
										AssignedTo = $accountName
										AssignedToSID = $account
										Type = "Individual User or Custom Group"
									}
								} catch {
									$issues += [PSCustomObject]@{
										Right = $sensitiveRights[$rightName]
										RightName = $rightName
										AssignedTo = $account
										AssignedToSID = $account
										Type = "Unknown SID"
									}
								}
							}
						} elseif ($account -notmatch '^\*S-1-') {
							# Direct username (not a SID) - this is a red flag
							$issues += [PSCustomObject]@{
								Right = $sensitiveRights[$rightName]
								RightName = $rightName
								AssignedTo = $account
								AssignedToSID = $null
								Type = "Individual Username"
							}
						}
					}
				}
			}
		}
		
		# Report and handle each finding
		if ($issues.Count -gt 0) {
			Write-Host "WARNING: Found $($issues.Count) potential security issue(s) in User Rights Assignments:" -ForegroundColor Yellow
			
			$accountsToRemove = @{}  # Dictionary: RightName -> Array of accounts to remove
			
			foreach ($issue in $issues) {
				Write-Host "  Right: $($issue.Right)" -ForegroundColor Yellow
				Write-Host "    Assigned to: $($issue.AssignedTo) [$($issue.Type)]" -ForegroundColor Red
				
				do {
					$answer = Read-Host "    Remove this assignment? Y/N"
					$answer = $answer.ToLower()
					
					if ($answer -ne "y" -and $answer -ne "n") {
						Write-Host "    Please input a valid answer (Y/N)!"
					}
				} while ($answer -ne "y" -and $answer -ne "n")
				
				if ($answer -eq "y") {
					if (-not $accountsToRemove.ContainsKey($issue.RightName)) {
						$accountsToRemove[$issue.RightName] = @()
					}
					# Store the SID if available, otherwise the account name
					$accountsToRemove[$issue.RightName] += if ($issue.AssignedToSID) { $issue.AssignedToSID } else { $issue.AssignedTo }
					$modificationsNeeded = $true
					Write-Host "    Marked for removal." -ForegroundColor Green
				} else {
					Write-Host "    Keeping assignment."
				}
			}
			
			# Apply removals if any were marked
			if ($modificationsNeeded) {
				Write-Host "Applying User Rights Assignment changes..."
				
				# Re-read the content to modify
				$content = Get-Content "$env:TEMP\secpol_rights.cfg"
				$newContent = @()
				$inPrivilegeSection = $false
				
				foreach ($line in $content) {
					if ($line -match "^\[Privilege Rights\]") {
						$inPrivilegeSection = $true
						$newContent += $line
						continue
					}
					
					if ($line -match "^\[.*\]" -and $line -notmatch "^\[Privilege Rights\]") {
						$inPrivilegeSection = $false
					}
					
					if ($inPrivilegeSection -and $line -match "^(\w+)\s*=\s*(.+)") {
						$rightName = $matches[1]
						$assignedTo = $matches[2]
						
						if ($accountsToRemove.ContainsKey($rightName)) {
							# Remove specified accounts from this right
							$accounts = $assignedTo -split ',' | ForEach-Object { $_.Trim() }
							$accountsToRemoveList = $accountsToRemove[$rightName]
							
							$remainingAccounts = $accounts | Where-Object { 
								$account = $_
								$keep = $true
								foreach ($toRemove in $accountsToRemoveList) {
									if ($account -eq $toRemove) {
										$keep = $false
										break
									}
								}
								$keep
							}
							
							if ($remainingAccounts.Count -gt 0) {
								$newContent += "$rightName = $($remainingAccounts -join ',')"
							} else {
								# If no accounts remain, comment out or skip the line
								$newContent += "; $line"
							}
						} else {
							$newContent += $line
						}
					} else {
						$newContent += $line
					}
				}
				
				# Save settings
				$newContent | Set-Content "$env:TEMP\secpol_rights_modified.cfg"
				
				# Apply the modified security policy
				Write-Host "Importing modified security policy..."
				secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol_rights_modified.cfg" /areas USER_RIGHTS /quiet | Out-Null
				
				if ($LASTEXITCODE -eq 0) {
					Write-Host "User Rights Assignments updated successfully." -ForegroundColor Green
				} else {
					Write-Host "Warning: Security policy import may have encountered issues. Exit code: $LASTEXITCODE" -ForegroundColor Yellow
				}
				
				Remove-Item "$env:TEMP\secpol_rights_modified.cfg" -ErrorAction SilentlyContinue
			} else {
				Write-Host "No changes were made to User Rights Assignments."
			}
			
		} else {
			Write-Host "No suspicious individual user assignments found in User Rights." -ForegroundColor Green
		}
		
		Remove-Item "$env:TEMP\secpol_rights.cfg" -ErrorAction SilentlyContinue
		
	} catch {
		Write-Host "Failed to check User Rights Assignments. Error: $_"
		Remove-Item "$env:TEMP\secpol_rights.cfg" -ErrorAction SilentlyContinue
		Remove-Item "$env:TEMP\secpol_rights_modified.cfg" -ErrorAction SilentlyContinue
	}
}
Check-UserRightsAssignment

Write-Host "`n==============================================================================="
Write-Host "Script execution completed!"
Write-Host "==============================================================================="
