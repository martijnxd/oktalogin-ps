function mfaPush {
    param(
        $oktadomain,
        $stateToken,
        $pushFactorId,
        $session
    )
    
    Write-Output "Sending Okta Verify push notification..."
    $status = "MFA_CHALLENGE"
    $tries = 0
    $body = '{"stateToken":"' + $stateToken + '"}'
    $url = 'https://' + $oktadomain + '/api/v1/authn/factors/' + $pushFactorId[0] + '/verify'

    while ($status -eq "MFA_CHALLENGE" -and $tries -lt 60 ) {
        $verifyAndPoll = iwr  $url  `
            -WebSession $session `
            -Method 'POST' `
            -ContentType 'application/json' `
            -Body $body | Convertfrom-Json
        $status = $verifyAndPoll.status
        $tries = $tries++
        Write-Output "Polling for push approve..."
        sleep 5
    }
    if ( $status -ne "SUCCESS" ) {
        Write-Output "MFA failed. Try again."
    }  else {
        $sessionToken=$verifyAndPoll.sessionToken
        $url='https://' + $oktadomain + '/login/sessionCookieRedirect?checkAccountSetupComplete=true&token='+$sessionToken+'&redirectUrl=https%3A%2F%2F'+$oktadomain+'.'+$oktadomain+'%2Fuser%2Fnotifications'
        $sessionId=iwr $url -WebSession $session  
        write-output "logged in" 
    }
    return $sessionToken, $sessionId,$session

}   

function okta-login {
    param (
        $username,
        $oktadomain,
        $password
    )
    $password = ConvertFrom-SecureString $password -AsPlainText
    if ($iswindows) {
        $body = '{"username":"' + $username + '","password":"' + $password + '"}'
        $url = 'https://' + $oktadomain + '/api/v1/authn'
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $jsonResult = iwr  $url  `
            -WebSession $session `
            -Method 'POST' `
            -ContentType 'application/json' `
            -Body $body | Convertfrom-Json
    }
    Write-host $jsonResult
    $status = $jsonResult.status
    $pushFactorID = $jsonResult._embedded.factors.id 
    if ($status.errorCode -eq "E0000004") {
        Write-Error "authentication failed"
    }
    if ($status -eq "SUCCESS") {
        $sessionToken = $jsonResult.sessionToken
    }
    if ($status -eq "MFA_REQUIRED") {
        Write-Host "mfa required"
        mfaPush -oktadomain $oktadomain -statetoken $jsonResult.stateToken -pushfactorid $pushFactorID -session $session
    }
    return $sessionToken, $session
}
$oktadomain = "*org*.okta.com"
$username = "*name@mail.com*"
$password = Read-Host -AsSecureString 'Enter password'
okta-login -username $username -password $password -oktadomain $oktadomain
