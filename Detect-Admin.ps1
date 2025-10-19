Import-Module ActiveDirectory

# Define Target Machine for Remote Execution
$TargetMachine = "WIN-11-X64-1"
$RunRemotely = $true  # Change to $false to run locally

# Define the Domain Admin Group
$DomainAdminGroup = "Domain Admins"

# Get domain admins
$DomainAdmins = Get-ADGroupMember -Identity $DomainAdminGroup | Select-Object -ExpandProperty SamAccountName

# Define Keywords for Credential Search
$keywords = "password", "credential", "token", "secret", "key", "username", "login", "pass"

# Define binary file extensions to ignore
$binaryExtensions = @("exe", "dll", "zip", "iso", "msi", "img", "bin")

# Function Definitions INSIDE the Remote Script Block
$ScriptBlock = {
    param ($DomainAdmins, $keywords, $binaryExtensions)

    # Function to Check Logged-In Users
    function Check-DomainAdmins {
        param ($DomainAdmins)

        # Get Logged-In Users
        $LoggedInUsers = quser 2>$null | Select-Object -Skip 1 | ForEach-Object {
            ($_.Trim() -replace '\s{2,}', ',').Split(',')[0] -replace '^>', ''
        }

        # Check if any logged-in user is a Domain Admin
        $DetectedAdmins = $LoggedInUsers | Where-Object { $_ -in $DomainAdmins }
        if ($DetectedAdmins) {
            Write-Host "[ALERT] Domain Admins logged in: $($DetectedAdmins -join ', ')" -ForegroundColor Red
        } else {
            Write-Host "[INFO] No domain admin sessions found." -ForegroundColor Green
        }
    }

    # Function to Check User Folders
    function Check-UserFolders {
        param ($DomainAdmins)

        $UsersFolders = Get-ChildItem -Path "C:\Users" | Select-Object -ExpandProperty Name
        $DetectedProfiles = $UsersFolders | Where-Object { $_ -in $DomainAdmins }

        if ($DetectedProfiles) {
            Write-Host "[ALERT] Domain Admin profiles exist: $($DetectedProfiles -join ', ')" -ForegroundColor Magenta
        } else {
            Write-Host "[INFO] No domain admin profiles found." -ForegroundColor Green
        }
    }

    # Function to Check Running Processes
    function Check-RunningProcesses {
        param ($DomainAdmins)

        # Get running processes and their owners
        $RunningProcesses = Get-WmiObject Win32_Process | ForEach-Object {
            $process = $_
            try {
                $owner = ($process.GetOwner().User) -join ""  # Get process owner
                if ($owner) {
                    [PSCustomObject]@{
                        ProcessId = $process.ProcessId
                        Name      = $process.Name
                        Owner     = $owner
                    }
                }
            } catch {
                # Ignore processes that do not have an owner
            }
        } | Where-Object { $_ -ne $null }  # Remove null values

        # Filter processes owned by Domain Admins
        $AdminProcesses = $RunningProcesses | Where-Object { $_.Owner -in $DomainAdmins }

        if ($AdminProcesses.Count -gt 0) {
            Write-Host "[ALERT] Running processes owned by Domain Admins detected!" -ForegroundColor Red
            $AdminProcesses | Format-Table -AutoSize
        } else {
            Write-Host "[INFO] No processes owned by domain admins found." -ForegroundColor Green
        }
    }

    # Get all user profiles on the machine
    $UserProfiles = Get-ChildItem -Path "C:\Users" -Directory | Select-Object -ExpandProperty FullName

    # Generate paths dynamically for each user
    $paths = @()
    foreach ($profile in $UserProfiles) {
        $paths += "$profile\Documents"
        $paths += "$profile\Downloads"
        $paths += "$profile\AppData\Roaming\Microsoft\Credentials"
    }

    # Function to Check for Credential Files on Disk
    function Check-CredentialFiles {
        param ($keywords, $paths, $binaryExtensions)

        $foundFiles = @()
        foreach ($path in $paths) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { ($_ -ne $null) -and ($_.Extension -notin $binaryExtensions) } # Skip binary files

            foreach ($file in $files) {
                try {
                    # Read first 10 lines to check if it's a text file
                    $content = Get-Content -Path $file.FullName -TotalCount 10 -ErrorAction Stop

                    # If readable, check for credentials
                    $matches = Select-String -InputObject $content -Pattern ($keywords -join "|") -ErrorAction SilentlyContinue
                    if ($matches) {
                        $foundFiles += $file.FullName
                    }
                } catch {
                    # Ignore unreadable binary files
                }
            }
        }

        if ($foundFiles.Count -gt 0) {
            Write-Host "[ALERT] Possible credential files found:" -ForegroundColor Red
            $foundFiles | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        } else {
            Write-Host "[INFO] No exposed credentials found on disk." -ForegroundColor Green
        }
    }

    # Function to Run the Checks Periodically
    function Run-Checks {
        param ($DomainAdmins, $keywords, $paths, $binaryExtensions)

        while ($true) {
            Check-DomainAdmins -DomainAdmins $DomainAdmins
            Check-UserFolders -DomainAdmins $DomainAdmins
            Check-RunningProcesses -DomainAdmins $DomainAdmins
            Check-CredentialFiles -keywords $keywords -paths $paths -binaryExtensions $binaryExtensions
            Start-Sleep -Seconds 60  # Wait 60 seconds before re-running
        }
    }

    Run-Checks -DomainAdmins $DomainAdmins -keywords $keywords -paths $paths -binaryExtensions $binaryExtensions
}

# Run the Script Locally or Remotely
if ($RunRemotely) {
    Write-Host "[INFO] Running script remotely on $TargetMachine" -ForegroundColor Cyan
    Invoke-Command -ComputerName $TargetMachine -ScriptBlock $ScriptBlock -ArgumentList $DomainAdmins, $keywords, $binaryExtensions
} else {
    Write-Host "[INFO] Running script locally..." -ForegroundColor Cyan
    Run-Checks -DomainAdmins $DomainAdmins -keywords $keywords -paths $paths -binaryExtensions $binaryExtensions
}
