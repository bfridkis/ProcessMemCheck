#Function for sending an email (Send-MailMessage cmdlet deprecated in Windows 2016 and higher)
function Send-Email([string[]]$to, [string[]]$from, [string[]]$cc, [string[]]$attachments, [string[]]$subject, [string[]]$smtpServer, [string[]]$mBody){
    $message = new-object Net.Mail.MailMessage;
    $message.From = new-object MailAddress($from);
    ForEach($address in $to) { 
        $message.To.Add($address);
    }
    ForEach($address in $cc) { 
        $message.Cc.Add($address);
    }
    $message.Subject = $subject
    $message.Body = $mBody;
    ForEach($attachment in $attachments) { 
        $attachmentFile = New-Object Net.Mail.Attachment($attachment);
        $message.Attachments.Add($attachmentFile);
    }

    $smtp = new-object Net.Mail.SmtpClient("10.100.95.35", "25");
    #$smtp.EnableSSL = $true;

    #$smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password);
    $smtp.send($message);
    write-host "Mail Sent" ; 
    $attachmentFile.Dispose();
 }

#Import Active Directory Module. Needed for retrieving the list of all domain nodes via 'Get-ADObject' cmdlet.
Import-Module ActiveDirectory

#Set all pertinent variables to $null in case values are left over from previous execution.
$processToMeasure = $utilizationThreshold = $utilizationThresholdExceeded = $results = $cleared = $errors = $null

#Process command line arguments.
([string]$args).split('-') | ForEach-Object { 
                                if ($_.Split(' ')[0] -eq "ProcessToMeasure") { $processToMeasure = $_.Split(' ')[1] }
                                if ($_.Split(' ')[0] -eq "UtilizationThreshold") { $utilizationThreshold = $_.Split(' ')[1] }
                             }
#If command line arguments not provided, prompt for processToMeasure and utilizationThreshold. 
#Also (if command line arguments are not provided), set $runAsScript = $false to provide a pause for reviewing console output. (See final if block.)
if ($processToMeasure -and $utilizationThreshold) { $runAsScript = $true } else { $runAsScript = $false }
if (!$processToMeasure) { $processToMeasure = Read-Host -prompt "`nName of Process to Measure " }
if (!$utilizationThreshold) { $utilizationThreshold = Read-Host -prompt "Utilization Threshold (% of total system memory to flag via email - leave blank for none) " }

#Set path and file name for temp file that will be used to track email output.
#This is so emails are only sent if new nodes get added to the exceedance report.
$flaggedNodesOutputFilePath = "E:\ProcessMemCheck\$($processToMeasure) MemCheck Exceedance\$($processToMeasure) Flagged Nodes.txt"

#Delete any record in the process's memcheck directories that are older than $daysToRetain (except for the flagged nodes file, used for email tracking).
$daysToRetain = 7
Get-ChildItem -Path "E:\ProcessMemCheck\$($processToMeasure) MemCheck*\" -Recurse -Force -ErrorAction Silent | 
Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt (Get-Date).AddDays(-$daysToRetain) -and $_.Name -ne "$($processToMeasure) Flagged Nodes.txt"} | 
Remove-Item -Force

Write-Host "`nRunning, please wait..."

$stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

$results = New-Object System.Collections.Generic.List[System.Object]
$cleared = New-Object System.Collections.Generic.List[System.Object]
$errors = New-Object System.Collections.Generic.List[System.Object]

#Create process specific memcheck output and exceedance directories if non-existent, as well as flagged file for email tracking.
if (!(Test-Path -Path "E:\ProcessMemCheck\$($processToMeasure) MemCheck Exceedance")) {New-Item "E:\ProcessMemCheck\$($processToMeasure) MemCheck Exceedance" -ItemType directory -force >$null}
if (!(Test-Path -Path "E:\ProcessMemCheck\$($processToMeasure) MemCheck Output")) {New-Item "E:\ProcessMemCheck\$($processToMeasure) MemCheck Output" -ItemType directory -force >$null}
if (!(Test-Path -Path $flaggedNodesOutputFilePath)) {
    $flaggedNodesOutputFile = New-Item $flaggedNodesOutputFilePath -ItemType file -force
    $flaggedNodesOutputFile.attributes = "Hidden"
}

#For Testing...
#Get-ADObject -LDAPFilter "(objectClass=computer)" | where-object { $_.name -like "*DEV*" } | select-object -expandproperty name -outvariable comps > $null

#Get a list of all domain computers. Filter out non-Windows machines, laptops, and L3.5 machines.
#For each, get memory statistics for target process (processToMeasure) and add to results container or if error, error container.
Get-ADObject -LDAPFilter "(objectClass=computer)" |
Where-Object { $_.Name -notlike "PCNVS*" -and $_.Name -notlike "DEVVS*" -and $_.Name -notlike "PCNVC*" -and $_.Name -notlike "PCNLAP*" -and $_.DistinguishedName -notlike "*OU=L35_DMZ*" } |
Select-Object -expandproperty Name -outvariable comps > $null
$comps | ForEach-Object {
    $currComp = $_
    Try { 
        #Ping once and if fail, abort with error and move on (to speed the processing)
        Test-Connection $_ -Count 1 -ErrorAction Stop > $null
        Try {
            #Get total system memory
            $totalSystemMemory = (Get-WmiObject -ComputerName $currComp -ClassName 'Cim_PhysicalMemory' -ErrorAction Stop | 
                                  Measure-Object -Property Capacity -Sum).Sum
            
            #Get process memory, perform calculations, and add to results container or if error, error container
            Try {
                $result = get-process -name $processToMeasure -ComputerName $currComp -ErrorAction Stop | 
                          select-object -ExpandProperty workingset
                $resultMB = [math]::Round(($result/1MB), 2)
                $resultPercentSystemTotal = [math]::Round(($result/$totalSystemMemory) * 100, 2)
                $results.Add([PSCustomObject]@{'Hostname'=$currComp ; 
                                               'MemUsage' = $resultMB ; 
                                               'PercentSystemTotal' = $resultPercentSystemTotal ;
                                               'TotalSystemMemory' = $($totalSystemMemory / 1GB)
                                               })
                
                #If a utilization threshold has been specified, add the node to the flag file (for email tracking) if the threshold is exceeded (and it's not already there),
                #or remove it from the flag file if the threshold is no longer exceeded (and it is there).
                if($utilizationThreshold) {
                    if(!(Select-String -Path $flaggedNodesOutputFilePath -Pattern $currComp) -and $resultPercentSystemTotal -gt $utilizationThreshold) { 
                        $currComp | Add-Content -Path $flaggedNodesOutputFilePath 
                    }
                    elseif ((Select-String -Path $flaggedNodesOutputFilePath -Pattern "$currComp -emailed") -and $resultPercentSystemTotal -lt $utilizationThreshold) { 
                        $flaggedNodesOutputFileUpdate = Get-Content -Path $flaggedNodesOutputFilePath | Where-Object {$_ -ne "$currComp -emailed"}
                        $flaggedNodesOutputFileUpdate | Set-Content $flaggedNodesOutputFilePath

                        #Add node to cleared containter if it was just removed from the exceedance list (and therefore flag file).
                        $cleared.Add([PSCustomObject]@{'Hostname'=$currComp ; 
                                                       'MemUsage' = $resultMB ; 
                                                       'PercentSystemTotal' = $resultPercentSystemTotal ;
                                                       'TotalSystemMemory' = $($totalSystemMemory / 1GB)
                                                      })
                    }
                }
            }
            Catch { $errors.Add([PSCustomObject]@{'Hostname'=$currComp ; 'Exception' = $_.Exception.Message}) }
        }
        Catch { $errors.Add([PSCustomObject]@{'Hostname'=$currComp ; 'Exception' = $_.Exception.Message}) }
    }
    Catch{ 
         $errors.Add([PSCustomObject]@{'Hostname'=$currComp ; 'Exception' = $_.Exception.Message})
    }
}

$elapsedTime = $stopWatch.Elapsed.TotalSeconds

$timeStamp = Get-Date -Format MMddyyyy_HHmmss

#Sort and format for output.
$results | Sort-Object PercentSystemTotal -Descending | Select-Object Hostname, @{n='Memory Usage (MB)' ; e= { "{0:N2}" -f $_.MemUsage }},
                                                                                @{n='Percentage of Total System Memory' ; e= { "{0:N2}" -f $_.PercentSystemTotal }},
                                                                                @{n='Total System Memory (GB)' ; e= {$_.TotalSystemMemory}} -OutVariable Export >$null

#Export the data to file.
$outputFile = "E:\ProcessMemCheck\$($processToMeasure) MemCheck Output\$($processToMeasure) MemCheck Output-$timeStamp.csv"
$outputString = "$processToMeasure Memory Usage Results"
Add-Content -Path $outputFile -Value $outputString
$Export | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $outputFile

#Add the errors to the output file.
$outputString = "`r`n** Errors **"
Add-Content -Path $outputFile -Value $outputString
$errors | Select-Object @{ n = 'Hostname' ; e = {$_.Hostname}},
                        @{ n = 'Exceptions Generated' ; e = {$_.Exception}} |
          Sort-Object Hostname | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $outputFile

#Show output in console.
Write-Host "`n$processToMeasure Memory Usage Results"
$export | Format-Table Hostname, @{n='Memory Usage (MB)' ; e= { "{0:N2}" -f $_."Memory Usage (MB)" } ; a="right"},
                                 @{n='Percentage of Total System Memory' ; e= { "{0:N2}" -f $_."Percentage of Total System Memory" } ; a="right"},
                                 @{n='Total System Memory (GB)' ; e= {$_."Total System Memory (GB)"}}
#Show errors in console.
Write-Host "Errors:"
$errors | Sort-Object Hostname | Format-Table

write-output "`nExecution Complete. $(if ($elapsedTime -gt 60) { "$([math]::Round($elapsedTime/60, 2)) minutes" } else { "$([math]::Round($elapsedTime, 2)) seconds" })."

#If utilization threshold is specified create exceedance report and email if applicable.
if($utilizationThreshold) {

    $recipients = @("ben.j.fridkis@p66.com", "john.gusewelle@p66.com")
    $Cc = @("Darrin.R.Feather@p66.com")
    #$recipients = @("ben.j.fridkis@p66.com")

    #Get data for all nodes for which memory utilization threshold is exceeded.
    $export.Where({ $([convert]::ToDouble($utilizationThreshold)) -gt $_."Percentage of Total System Memory"  }, "Until") | 
    Select-Object -OutVariable utilizationThresholdExceeded > $null

    #If any nodes have exceeded the threshold, output to exceedance report file.
    if($utilizationThresholdExceeded.Count -gt 0) {
        $ExceedanceOutputFile = "E:\ProcessMemCheck\$($processToMeasure) MemCheck Exceedance\$($processToMeasure) MemCheck Exceedance Report-$timeStamp.csv"
        $outputString = "$processToMeasure Memory Usage Exceedance Report (> $utilizationThreshold% Total System Memory)"
        Add-Content -Path $ExceedanceOutputFile -Value $outputString
        $utilizationThresholdExceeded | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $ExceedanceOutputFile

        #Check to see if node is in the flag file and is not notated with "-emailed" string. If so, email the exceedance report (as at least one new node has been added to it). 
        $unprocessedFlagCount = (Get-Content $flaggedNodesOutputFilePath | Where-Object { ($_ -notlike "*-emailed" -and $_ -ne "") } | Measure-Object).Count
        if($unprocessedFlagCount -gt 0) {
            #Send-MailMessage -From PCNSMS04-WRR@p66.com -To $recipients -Cc $Cc -Subject "$processToMeasure Memory Utilization Threshold Exceedance Report-$timestamp"  `
            #                 -Attachments $ExceedanceOutputFile -SmtpServer 10.100.95.35
            Send-Email -From PCNSMS04-WRR@p66.com -To $recipients -Cc $Cc -Subject "$processToMeasure Memory Utilization Threshold Exceedance Report-$timestamp"  `
                             -Attachments $ExceedanceOutputFile -SmtpServer 10.100.95.35
            #Append " -emailed" string to all nodes after exceedance report is sent.
            $flaggedNodesOutputFileUpdate = $null
            Get-Content $flaggedNodesOutputFilePath | ForEach-Object { if($_ -like "*-emailed") {$flaggedNodesOutputFileUpdate += "$_`r`n" } elseif($_ -ne "") {$flaggedNodesOutputFileUpdate += "$_ -emailed`r`n" } }
            $flaggedNodesOutputFileUpdate | Set-Content -Path $flaggedNodesOutputFilePath -force
        }
    }
    #If any nodes were previously on the exceedance report and have now been removed, email list of nodes cleared from exceedance report.
    if($cleared.Count -gt 0) {
        $outputString = "$processToMeasure Memory Usage Exceedances CLEARED (now < $utilizationThreshold% Total System Memory)"
        $tempFileForClearedResults = New-Item "E:\ProcessMemCheck\$($processToMeasure) MemCheck Exceedance\$($processToMeasure) MemCheck Exceedance CLEARED-$timeStamp.csv" -ItemType file -force
        Add-Content -Path $tempFileForClearedResults -Value $outputString
        $cleared | Sort-Object PercentSystemTotal -Descending | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $tempFileForClearedResults
        #Send-MailMessage -From PCNSMS04-WRR@p66.com -To $recipients -Cc $Cc -Subject "$processToMeasure Memory Utilization Threshold Exceedances CLEARED-$timestamp" `
        #                 -Attachments $tempFileForClearedResults -SmtpServer 10.100.95.35
        Send-Email -From PCNSMS04-WRR@p66.com -To $recipients -Cc $Cc -Subject "$processToMeasure Memory Utilization Threshold Exceedances CLEARED-$timestamp" `
             -Attachments $tempFileForClearedResults -SmtpServer 10.100.95.35
        remove-item $tempFileForClearedResults
    }
}

if(!$runAsScript) {
    Write-Host "`n"
    Pause
}

# Resources
# https://stackoverflow.com/questions/1984186/what-is-private-bytes-virtual-bytes-working-set
# https://stackoverflow.com/questions/14726143/get-memory-usage-as-reported-by-windows-8-task-manager
# https://stackoverflow.com/questions/26552223/get-process-with-total-memory-usage
# https://stackoverflow.com/questions/7954781/whats-the-difference-between-working-set-and-commit-size#:~:text=1%20Answer&text=From%20here%2C%20the%20working%20set%20is%3A&text=So%20you%20can%20think%20of,other%20than%20the%20page%20file).
# https://stackoverflow.com/questions/4857792/powershell-reference-a-property-that-contains-a-space
# https://stackoverflow.com/questions/48425562/powershell-add-content-should-create-path-but-throws-exception-could-not-find-a
# https://stackoverflow.com/questions/41871147/find-specific-string-in-textfile-powershell/41871326
# https://stackoverflow.com/questions/226596/powershell-array-initialization
# https://stackoverflow.com/questions/10241816/powershell-send-mailmessage-email-to-multiple-recipients
# https://social.technet.microsoft.com/Forums/en-US/33665b03-d383-41ed-a836-fd83c217b3f1/making-files-hidden-with-powershell?forum=ITCG
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.1