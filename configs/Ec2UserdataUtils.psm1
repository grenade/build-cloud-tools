<#
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
.Synopsis
  Utility functions for bootstraping an AWS EC2 instance with cloud-tools (https://github.com/mozilla/build-cloud-tools)
#>
function Write-Log {
  <#
  .Synopsis
    Logs to the userdata run log file, with timestamps.
  .Parameter message
    The body of the log message
  .Parameter severity
    The severity of the message, to enable filtering in log aggregators or reporting.
  .Parameter path
    The full path to the log file.
  #>
  param (
    [string] $message,
    [string] $severity = 'INFO',
    [string] $path = ('{0}\log\userdata-run.log' -f $env:SystemDrive)
  )
  if (!(Test-Path $path)) {
    [Environment]::SetEnvironmentVariable('OutputToConsole', 'true', 'Process')
  }
  $formattedMessage = ('{0} [{1}] {2}' -f [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss zzz"), $severity, $message)
  Add-Content -Path $path -Value $formattedMessage
  switch ($severity) 
  {
    #{Error | Warning | Information | SuccessAudit | FailureAudit}
    'DEBUG' {
      $foregroundColor = 'DarkGray'
      $entryType = 'SuccessAudit'
      $eventId = 2
    }
    'WARN' {
      $foregroundColor = 'Yellow'
      $entryType = 'Warning'
      $eventId = 3
    }
    'ERROR' {
      $foregroundColor = 'Red'
      $entryType = 'Error'
      $eventId = 4
    }
    default {
      $foregroundColor = 'White'
      $entryType = 'Information'
      $eventId = 1
    }
  }
  if ($env:OutputToConsole -eq 'true') {
    Write-Host -Object $formattedMessage -ForegroundColor $foregroundColor
  }
  $logName = 'Application'
  $source = 'Userdata'
  if (!([Diagnostics.EventLog]::Exists($logName)) -or !([Diagnostics.EventLog]::SourceExists($source))) {
    New-EventLog -LogName $logName -Source $source
  }
  Write-EventLog -LogName $logName -Source $source -EntryType $entryType -Category 0 -EventID $eventId -Message $message
}

function Send-Log {
  <#
  .Synopsis
    Mails the specified logfile to the configured recipient(s)
  .Parameter logfile
    The full path to the log file to be mailed.
  .Parameter subject
    The subject line of the message.
  .Parameter to
    The recipient(s) of the message.
  .Parameter from
    The sender of the message.
  .Parameter smtpServer
    The smtp server that relays log messages.
  #>
  param (
    [string] $logfile,
    [string] $subject,
    [string] $to,
    [string] $from = ('{0}@{1}.{2}' -f $env:USERNAME, $env:COMPUTERNAME, $env:USERDOMAIN),
    [string] $smtpServer = 'smtp.mail.scl3.mozilla.com'
  )
  if (Test-Path $logfile) {
    Send-MailMessage -To $to -Subject $subject -Body ([IO.File]::ReadAllText($logfile)) -SmtpServer $smtpServer -From $from
  } else {
    Write-Log -message ("{0} :: skipping log mail, file: {1} not found" -f $($MyInvocation.MyCommand.Name), $logfile) -severity 'WARN'
  }
}

function Enable-UserdataPersist {
  <#
  .Synopsis
    Sets Ec2ConfigService Ec2HandleUserData to enabled in config.
  .Description
    Modifies Ec2ConfigService config file and logs settings at time of check.
  .Parameter ec2SettingsFile
    The full path to the config file for Ec2ConfigService.
  #>
  $startup = ('{0}\System32\GroupPolicy\Machine\Scripts\Startup' -f $env:SystemRoot)
  $userscript = ('{0}\Amazon\EC2ConfigService\Scripts\UserScript.ps1' -f $env:ProgramFiles)
  if (!(Test-Path $startup)) {
    New-Item -ItemType Directory -Force -Path $startup
  }
  if ((Test-Path $userscript) -and !(Test-Path ('{0}\UserScript.ps1' -f $startup))) {
    Set-ExecutionPolicy RemoteSigned -force
    Copy-Item $userscript $startup
    Disable-Service -serviceName 'EC2Config'
  }
}

function Stop-ComputerWithDelay {
  <#
  .Synopsis
    Shuts down the computer and optionally restarts, logging a reason to the event log.
  .Parameter reason
    The reason for the shutdown or reboot.
  .Parameter delayInSeconds
    The time delay in seconds before shutting down
  .Parameter restart
    Whether or not to restart after shutdown
  #>
  param (
    [string] $reason,
    [int] $delayInSeconds = 10,
    [switch] $restart
  )
  Write-Log -message ('shutting down with reason: {0}' -f $reason) -severity 'INFO'
  if ($restart) {
    $stopArgs = @('-r', '-t', $delayInSeconds, '-c', $reason, '-f', '-d', 'p:4:1')
  } else {
    $stopArgs = @('-s', '-t', $delayInSeconds, '-c', $reason, '-f', '-d', 'p:4:1')
  }
  & 'shutdown' $stopArgs
}

function Does-FileContain {
  <#
  .Synopsis
    Determine if a file contains the specified string
  .Parameter needle
    The string to search for.
  .Parameter haystack
    The full path to the file to be checked.
  #>
  param (
    [string] $haystack,
    [string] $needle
  )
  if (((Get-Content $haystack) | % { $_ -Match "$needle" }) -Contains $true) {
    return $true
  } else {
    return $false
  }
}

function Has-PuppetRunSuccessfully {
  <#
  .Synopsis
    Determine if a successful puppet run has completed
  .Parameter puppetLog
    The full path to the puppet log file.
  #>
  param (
    [string] $puppetLog
  )
  if ((Test-Path $puppetLog) -and (Does-FileContain -haystack $puppetLog -needle "Puppet \(notice\): Finished catalog run")) {
    return $true
  } else {
    return $false
  }
}

function Disable-Service {
  <#
  .Synopsis
    Stops and disables a windows service
  .Parameter serviceName
    the name of the service to be disabled
  #>
  param (
    [string] $serviceName
  )
  Write-Log -message ('stopping and disabling service: {0}' -f $serviceName) -severity 'INFO'
  Get-Service $serviceName | Stop-Service -PassThru | Set-Service -StartupType disabled
}

function Disable-WindowsUpdate {
  <#
  .Synopsis
    Stops and disables the windows update service 
  #>
  $autoUpdateSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
  if ($autoUpdateSettings.NotificationLevel -ne 1) {
    Write-Log -message 'disabling Windows Update notifications' -severity 'INFO'
    $autoUpdateSettings.NotificationLevel=1
    $autoUpdateSettings.Save()
  } else {
    Write-Log -message 'detected disabled Windows Update notifications' -severity 'DEBUG'
  }
  Disable-Service -serviceName 'wuauserv'
}

function Disable-PuppetService {
  <#
  .Synopsis
    Stops and disables the puppet service and deletes the RunPuppet scheduled task
  #>
  Disable-Service -serviceName 'puppet'
  $ss = New-Object -com Schedule.Service 
  $ss.Connect()
  if (($ss.GetFolder("\").GetTasks(0) | Select Name | ? {$_.Name -eq 'RunPuppet'}) -ne $null) {
    Write-Log -message 'deleting RunPuppet scheduled task' -severity 'INFO'
    $schtasksArgs = @('/delete', '/tn', 'RunPuppet', '/f')
    & 'schtasks' $schtasksArgs
  }
}

function Install-Certificates {
  param (
    [string] $ini = ('{0}\Mozilla\RelOps\ec2.ini' -f $env:ProgramData),
    [string] $sslPath = ('{0}\PuppetLabs\puppet\var\ssl' -f $env:ProgramData),
    [hashtable] $certs = @{
      'ca' = ('{0}\certs\ca.pem' -f $sslPath);
      'pub' = ('{0}\certs\{1}.{2}.pem' -f $sslPath, $env:COMPUTERNAME, $env:USERDOMAIN);
      'key' = ('{0}\private_keys\{1}.{2}.pem' -f $sslPath, $env:COMPUTERNAME, $env:USERDOMAIN)
    }
  )
  if ((Test-Path $certs['ca']) -and ((Get-Item $certs['ca']).length -gt 0) -and (Test-Path $certs['pub']) -and ((Get-Item $certs['pub']).length -gt 0) -and (Test-Path $certs['key']) -and ((Get-Item $certs['key']).length -gt 0)) {
    Write-Log -message ("{0} :: certificates detected" -f $($MyInvocation.MyCommand.Name)) -severity 'INFO'
    return $true
  } elseif (Test-Path $ini) {
    Write-Log -message ("{0} :: installing certificates" -f $($MyInvocation.MyCommand.Name)) -severity 'INFO'
    $deployConfig = Get-IniContent -FilePath $ini
    Remove-Item -path $ini -force
    foreach ($folder in @(('{0}\private_keys' -f $sslPath), ('{0}\certs' -f $sslPath))) {
      if (Test-Path $folder) {
        Remove-Item -path $folder -recurse -force
      }
      New-Item -ItemType Directory -Force -Path $folder
    }
    $url = 'https://{0}/deploy/getcert.cgi' -f $deployConfig['deploy']['hostname']
    $cc = New-Object Net.CredentialCache
    $cc.Add($url, "Basic", (New-Object Net.NetworkCredential($deployConfig['deploy']['username'],$deployConfig['deploy']['password'])))
    $wc = New-Object Net.WebClient
    $wc.Credentials = $cc
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    Invoke-Command -ScriptBlock {
      $wd = $(Get-Location).Path
      cd $sslPath
      $shArgs = @('set', 'PATH=/c/Program Files/Git/usr/bin:$PATH')
      & ('{0}\Git\usr\bin\sh' -f $env:ProgramFiles) $shArgs
      $wc.DownloadString($url) | & ('{0}\Git\usr\bin\sh' -f $env:ProgramFiles)
      cd $wd
      # todo: set permissions on downloaded key files
    }
    return $true
  } else {
    Write-Log -message ("{0} :: unable to install certificates" -f $($MyInvocation.MyCommand.Name)) -severity 'ERROR'
    return $false
  }
}

function Run-Puppet {
  <#
  .Synopsis
    Runs the puppet agent
  .Description
    Runs the puppetization vbscript
    Runs the puppet agent in cli mode, logging to an output file
    Deletes the RunPuppet scheduled task
  .Parameter hostname
    The hostname of the instance, required for facter env vars.
  .Parameter domain
    The domain of the instance, required for facter env vars.
  #>
  param (
    [string] $puppetServer = 'puppet',
    [string] $logdest,
    [string] $environment = $null
  )
  if (Install-Certificates) {
    $puppetConfig = @{
      'main' = @{
        'logdir' = '$vardir/log/puppet';
        'rundir' = '$vardir/run/puppet';
        'ssldir' = '$vardir/ssl'
      };
      'agent' = @{
        'classfile' = '$vardir/classes.txt';
        'localconfig' = '$vardir/localconfig';
        'server' = 'releng-puppet1.srv.releng.use1.mozilla.com';
        'certificate_revocation' = 'false';
        'pluginsync' = 'true';
        'usecacheonfailure' = 'false'
      }
    }
    Out-IniFile -InputObject $puppetConfig -FilePath ('{0}\PuppetLabs\puppet\etc\puppet.conf' -f $env:ProgramData) -Encoding "ASCII" -Force
    Write-Log -message ("{0} :: running puppet agent, logging to: {1}" -f $($MyInvocation.MyCommand.Name), $logdest) -severity 'INFO'
    $puppetArgs = @('agent', '--test', '--detailed-exitcodes', '--server', $puppetServer, '--logdest', $logdest)
    if ($environment -ne $null) {
      $puppetArgs += '--environment'
      $puppetArgs += $environment
    }
    & ('{0}\Puppet Labs\Puppet\bin\puppet' -f $env:ProgramFiles) $puppetArgs
  } else {
    Write-Log -message ("{0} :: not attempting puppet agent run" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  $ss = New-Object -com Schedule.Service 
  $ss.Connect()
  if (($ss.GetFolder("\").gettasks(0) | Select Name | ? {$_.Name -eq 'RunPuppet'}) -ne $null) {
    Write-Log -message 'deleting RunPuppet scheduled task (again)' -severity 'INFO'
    $schtasksArgs = @('/delete', '/tn', 'RunPuppet', '/f')
    & 'schtasks' $schtasksArgs
  }
}

function Is-HostnameSetCorrectly {
  <#
  .Synopsis
    Determines if the hostname is correctly set
  .Parameter hostnameExpected
    The expected hostname of the instance.
  #>
  param (
    [string] $hostnameExpected
  )
  $hostnameActual = [System.Net.Dns]::GetHostName()
  if ("$hostnameExpected" -ieq "$hostnameActual") {
    return $true
  } else {
    Write-Log -message ('net dns hostname: {0}, expected: {1}' -f $hostnameActual, $hostnameExpected) -severity 'DEBUG'
    Write-Log -message ('computer name env var: {0}, expected: {1}' -f $env:COMPUTERNAME, $hostnameExpected) -severity 'DEBUG'
    return $false
  }
}

function Set-Hostname {
  <#
  .Synopsis
    Sets the hostname
  .Description
    - Sets the COMPUTERNAME environment variable at the machine level
    - Renames the computer
    - Adds the new hostname to the sysprep file, to prevent sysprep from reverting the hostname on reboot
  .Parameter hostname
    The required new hostname of the instance.
  #>
  param (
    [string] $hostname
  )
  [Environment]::SetEnvironmentVariable("COMPUTERNAME", "$hostname", "Machine")
  (Get-WmiObject Win32_ComputerSystem).Rename("$hostname")
  Write-Log -message ('hostname set to: {0}' -f $hostname) -severity 'INFO'
  $sysprepFile = ('{0}\Amazon\Ec2ConfigService\sysprep2008.xml' -f $env:ProgramFiles)
  [xml] $xml = Get-Content($sysprepFile)
  foreach ($settings in $xml.DocumentElement.settings) {
    if ($settings.pass -eq "specialize") {
      foreach ($component in $settings.component) {
        if ($component.name -eq "Microsoft-Windows-Shell-Setup") {
          if (-not $component.ComputerName) {
            $computerNameElement = $xml.CreateElement("ComputerName")
            $computerNameElement.AppendChild($xml.CreateTextNode("$hostname"))
            $component.AppendChild($computerNameElement)
            Write-Log -message ('computer name inserted to: {0}' -f $sysprepFile) -severity 'DEBUG'
          } else {
            if ($component.ComputerName.InnerText -ne "$hostname") {
              $component.ComputerName.InnerText = "$hostname"
              Write-Log -message ('computer name updated in: {0}' -f $sysprepFile) -severity 'DEBUG'
            }
          }
        }
      }
    }
  }
  $xml.Save($sysprepFile)
}

function Is-DomainSetCorrectly {
  <#
  .Synopsis
    Determines if the primary dns suffix is correctly set
  .Parameter domainExpected
    The expected primary dns suffix of the instance.
  #>
  param (
    [string] $domainExpected
  )
  if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NV Domain") {
    $primaryDnsSuffix = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain")."NV Domain"
  } elseif (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain") {
    $primaryDnsSuffix = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "Domain")."Domain"
  } else {
    $primaryDnsSuffix = $env:USERDOMAIN
  }
  if ("$domainExpected" -ieq "$primaryDnsSuffix") {
    return $true
  } else {
    Write-Log -message ('(nv) domain registry key: {0}, expected: {1}' -f $primaryDnsSuffix, $domainExpected) -severity 'DEBUG'
    return $false
  }
}

function Set-Domain {
  <#
  .Synopsis
    Set the primary DNS suffix (for FQDN)
  .Parameter domain
    The required new primary DNS suffix of the instance.
  #>
  param (
    [string] $domain
  )
  [Environment]::SetEnvironmentVariable("USERDOMAIN", "$domain", "Machine")
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\' -Name 'Domain' -Value "$domain"
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\' -Name 'NV Domain' -Value "$domain"
  Write-Log -message ('Primary DNS suffix set to: {0}' -f $domain) -severity 'INFO'
}

# determines if the log aggregator is correctly set
function Is-AggregatorConfiguredCorrectly {
  <#
  .Synopsis
    Determines if the log aggregator is correctly set
  .Parameter aggregator
    The fqdn of the log aggregator for the current aws region.
  #>
  param (
    [string] $aggregator
  )
  $conf = ('{0}\nxlog\conf\nxlog_target_aggregator.conf' -f ${env:ProgramFiles(x86)})
  if ((Test-Path $conf) -and (Does-FileContain -haystack $conf -needle $aggregator)) {
    return $true
  } else {
    return $false
  }
}

function Set-Aggregator {
  <#
  .Synopsis
    Sets the fqdn of the log aggregator for the current aws region.
  .Description
    Modifies the nxlog configuration file to point to the specified log aggregator and restarts the nxlog service.
  .Parameter aggregator
    The fqdn of the log aggregator for the current aws region.
  #>
  param (
    [string] $aggregator
  )
  $conf = ('{0}\nxlog\conf\nxlog_target_aggregator.conf' -f ${env:ProgramFiles(x86)})
  if (Test-Path $conf) {
    (Get-Content $conf) | Foreach-Object { $_ -replace "(Host .*)", "Host $aggregator" } | Set-Content $conf
    (Get-Content $conf) | Foreach-Object { $_ -replace "(Port .*)", "Port 1514" } | Set-Content $conf
    Write-Log -message "log aggregator set to: $aggregator" -severity 'INFO'
  }
  $conf = ('{0}\nxlog\conf\nxlog.conf' -f ${env:ProgramFiles(x86)})
  if (Test-Path $conf) {
    (Get-Content $conf) | Foreach-Object { $_ -replace "(define ROOT .*)", ('define ROOT {0}\nxlog' -f ${env:ProgramFiles(x86)}) } | Set-Content $conf
    (Get-Content $conf) | Foreach-Object { $_ -replace "(include .*)", 'include %ROOT%\conf\nxlog_*.conf' } | Set-Content $conf
    Write-Log -message "nxlog include config adjusted" -severity 'INFO'
  }
  Restart-Service nxlog
}

function Disable-Firewall {
  <#
  .Synopsis
    Disables the Windows Firewall for the specified profile.
  .Parameter profile
    The profile to disable the firewall under. Defaults to CurrentProfile.
  #>
  param (
    [string] $profile = 'AllProfiles',
    [string] $registryKey = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
  )
  Write-Log -message 'disabling Windows Firewall' -severity 'INFO'
  $netshArgs = @('advfirewall', 'set', $profile, 'state', 'off')
  & 'netsh' $netshArgs
  if (Test-Path $registryKey) {
    Write-Log -message 'removing Windows Firewall registry entries' -severity 'INFO'
    Remove-Item -path $registryKey -recurse -force
  }
}

function Flush-EventLog {
  <#
  .Synopsis
    Removes all entries from the event log. Used right before golden ami capture for a clean slate image.
  #>
  #Write-Log -message 'flushing the Windows EventLog' -severity 'INFO'
  #wevtutil el | % { wevtutil cl $_ }
}

function Set-PagefileSize {
  <#
  .Synopsis
  #>
  param (
    [int] $initialSize = 512,
    [int] $maximumSize = 512
  )
  $pf = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='c:\\pagefile.sys'"
  if (($initialSize -ne $pf.InitialSize) -or ($maximumSize -ne $pf.MaximumSize)) {
    Write-Log -message ('setting pagefile size: initial: {0} -> {1}, maximum: {2} -> {3}' -f $pf.InitialSize, $initialSize, $pf.MaximumSize, $maximumSize) -severity 'INFO'
    $sys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $sys.AutomaticManagedPagefile = $False
    $sys.Put()
    $pf.InitialSize = $initialSize
    $pf.MaximumSize = $maximumSize
    $pf.Put()
  }
}

function Get-IniContent {
  <#
  .Synopsis
    Gets the content of an INI file
  .Description
    Gets the content of an INI file and returns it as a hashtable
  .Notes
    Author      : Oliver Lipkau <oliver@lipkau.net>
    Blog        : http://oliver.lipkau.net/blog/
    Source      : https://github.com/lipkau/PsIni
                  http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
    Version     : 1.0 - 2010/03/12 - Initial release
                  1.1 - 2014/12/11 - Typo (Thx SLDR)
                                     Typo (Thx Dave Stiff)
    #Requires -Version 2.0
  .Inputs
    System.String
  .Outputs
    System.Collections.Hashtable
  .Parameter FilePath
    Specifies the path to the input file.
  .Example
    $FileContent = Get-IniContent "C:\myinifile.ini"
    -----------
    Description
    Saves the content of the c:\myinifile.ini in a hashtable called $FileContent
  .Example
    $inifilepath | $FileContent = Get-IniContent
    -----------
    Description
    Gets the content of the ini file passed through the pipe into a hashtable called $FileContent
  .Example
    C:\PS>$FileContent = Get-IniContent "c:\settings.ini"
    C:\PS>$FileContent["Section"]["Key"]
    -----------
    Description
    Returns the key "Key" of the section "Section" from the C:\settings.ini file
  .Link
    Out-IniFile
  #>
  [CmdletBinding()]
  Param (
    [ValidateNotNullOrEmpty()]
    [ValidateScript({(Test-Path $_)})]
    [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
    [string]$FilePath
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    Write-Log -message ("{0} :: Parsing file: {1}" -f $($MyInvocation.MyCommand.Name), $Filepath) -severity 'DEBUG'
    $ini = @{}
    switch -regex -file $FilePath {
      # Section
      "^\[(.+)\]$" {
        $section = $matches[1]
        $ini[$section] = @{}
        $CommentCount = 0
      }
      # Comment
      "^(;.*)$" {
        if (!($section)) {
            $section = "No-Section"
            $ini[$section] = @{}
        }
        $value = $matches[1]
        $CommentCount = $CommentCount + 1
        $name = "Comment" + $CommentCount
        $ini[$section][$name] = $value
      }
      # Key
      "(.+?)\s*=\s*(.*)" {
        if (!($section)) {
          $section = "No-Section"
          $ini[$section] = @{}
        }
        $name,$value = $matches[1..2]
        $ini[$section][$name] = $value
      }
    }
    Write-Log -message ("{0} :: Finished parsing file: {1}" -f $($MyInvocation.MyCommand.Name), $Filepath) -severity 'DEBUG'
    Return $ini
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

function Out-IniFile {
  <#
  .Synopsis
    Write hash content to INI file
  .Description
    Write hash content to INI file
  .Notes
    Author      : Oliver Lipkau <oliver@lipkau.net>
    Blog        : http://oliver.lipkau.net/blog/
    Source      : https://github.com/lipkau/PsIni
                  http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
    Version     : 1.0 - 2010/03/12 - Initial release
                  1.1 - 2012/04/19 - Bugfix/Added example to help (Thx Ingmar Verheij)
                  1.2 - 2014/12/11 - Improved handling for missing output file (Thx SLDR)
    #Requires -Version 2.0
  .Inputs
    System.String
    System.Collections.Hashtable
  .Outputs
    System.IO.FileSystemInfo
  .Parameter Append
    Adds the output to the end of an existing file, instead of replacing the file contents.
  .Parameter InputObject
    Specifies the Hashtable to be written to the file. Enter a variable that contains the objects or type a command or expression that gets the objects.
  .Parameter FilePath
    Specifies the path to the output file.
  .Parameter Encoding
    Specifies the type of character encoding used in the file. Valid values are "Unicode", "UTF7", "UTF8", "UTF32", "ASCII", "BigEndianUnicode", "Default", and "OEM". "Unicode" is the default.
    "Default" uses the encoding of the system's current ANSI code page.
    "OEM" uses the current original equipment manufacturer code page identifier for the operating system.
  .Parameter Force
    Allows the cmdlet to overwrite an existing read-only file. Even using the Force parameter, the cmdlet cannot override security restrictions.
  .Parameter PassThru
    Passes an object representing the location to the pipeline. By default, this cmdlet does not generate any output.
  .Example
    Out-IniFile $IniVar "C:\myinifile.ini"
    -----------
    Description
    Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini
  .Example
    $IniVar | Out-IniFile "C:\myinifile.ini" -Force
    -----------
    Description
    Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and overwrites the file if it is already present
  .Example
    $file = Out-IniFile $IniVar "C:\myinifile.ini" -PassThru
    -----------
    Description
    Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and saves the file into $file
  .Example
    $Category1 = @{“Key1”=”Value1”;”Key2”=”Value2”}
    $Category2 = @{“Key1”=”Value1”;”Key2”=”Value2”}
    $NewINIContent = @{“Category1”=$Category1;”Category2”=$Category2}
    Out-IniFile -InputObject $NewINIContent -FilePath "C:\MyNewFile.INI"
    -----------
    Description
    Creating a custom Hashtable and saving it to C:\MyNewFile.INI
  .Link
    Get-IniContent
  #>
  [CmdletBinding()]
  Param (
    [switch]$Append,

    [ValidateSet("Unicode","UTF7","UTF8","UTF32","ASCII","BigEndianUnicode","Default","OEM")]
    [Parameter()]
    [string]$Encoding = "Unicode",

    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$True)]
    [string]$FilePath,

    [switch]$Force,

    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
    [Hashtable]$InputObject,

    [switch]$Passthru
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    Write-Log -message ("{0} :: Writing file: {1}" -f $($MyInvocation.MyCommand.Name), $Filepath) -severity 'DEBUG'
    if ($append) {
      $outfile = Get-Item $FilePath
    } else {
      $outFile = New-Item -ItemType file -Path $Filepath -Force:$Force
    }
    if (!($outFile)) {
      throw "Could not create File"
    }
    foreach ($i in $InputObject.keys) {
      if (!($($InputObject[$i].GetType().Name) -eq "Hashtable")) {
        #No Sections
        Write-Log -message ("{0} :: Writing key: {1}" -f $($MyInvocation.MyCommand.Name), $i) -severity 'DEBUG'
        Add-Content -Path $outFile -Value "$i=$($InputObject[$i])" -Encoding $Encoding
      } else {
        #Sections
        Write-Log -message ("{0} :: Writing section: [{1}]" -f $($MyInvocation.MyCommand.Name), $i) -severity 'DEBUG'
        Add-Content -Path $outFile -Value "[$i]" -Encoding $Encoding
        foreach ($j in $($InputObject[$i].keys | Sort-Object)) {
          if ($j -match "^Comment[\d]+") {
            Write-Log -message ("{0} :: Writing comment: {1}" -f $($MyInvocation.MyCommand.Name), $j) -severity 'DEBUG'
            Add-Content -Path $outFile -Value "$($InputObject[$i][$j])" -Encoding $Encoding
          } else {
            Write-Log -message ("{0} :: Writing key: {1}" -f $($MyInvocation.MyCommand.Name), $j) -severity 'DEBUG'
            Add-Content -Path $outFile -Value "$j=$($InputObject[$i][$j])" -Encoding $Encoding
          }
        }
        Add-Content -Path $outFile -Value "" -Encoding $Encoding
      }
    }
    Write-Log -message ("{0} :: Finished writing file: {1}" -f $($MyInvocation.MyCommand.Name), $Filepath) -severity 'DEBUG'
    if ($PassThru) {
      Return $outFile
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

function Get-FileEncoding {
  <#
  .SYNOPSIS
  Gets file encoding.
  .DESCRIPTION
  The Get-FileEncoding function determines encoding by looking at Byte Order Mark (BOM).
  Based on port of C# code from http://www.west-wind.com/Weblog/posts/197245.aspx
  .EXAMPLE
  Get-ChildItem  *.ps1 | select FullName, @{n='Encoding';e={Get-FileEncoding $_.FullName}} | where {$_.Encoding -ne 'ASCII'}
  This command gets ps1 files in current directory where encoding is not ASCII
  .EXAMPLE
  Get-ChildItem  *.ps1 | select FullName, @{n='Encoding';e={Get-FileEncoding $_.FullName}} | where {$_.Encoding -ne 'ASCII'} | foreach {(get-content $_.FullName) | set-content $_.FullName -Encoding ASCII}
  Same as previous example but fixes encoding using set-content
  #>
  [CmdletBinding()]
  param (
   [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
   [string] $Path
  )
  [byte[]]$byte = get-content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $Path
  if ( $byte[0] -eq 0xef -and $byte[1] -eq 0xbb -and $byte[2] -eq 0xbf ) {
    return 'UTF8'
  }
  elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff) {
    return 'Unicode'
  }
  elseif ($byte[0] -eq 0 -and $byte[1] -eq 0 -and $byte[2] -eq 0xfe -and $byte[3] -eq 0xff) {
    return 'UTF32'
  }
  elseif ($byte[0] -eq 0x2b -and $byte[1] -eq 0x2f -and $byte[2] -eq 0x76) {
    return 'UTF7'
  }
  return 'ASCII'
}

function Set-IniValue {
  param (
    [string] $file,
    [string] $section,
    [string] $key,
    [string] $value
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    if (Test-Path $file) {
      Write-Log -message ("{0} :: detected ini file at: {1}" -f $($MyInvocation.MyCommand.Name), $file) -severity 'DEBUG'
      $config = Get-IniContent -FilePath $file
      if (-not $config.ContainsKey($section)) {
        $config.Add($section, @{})
        Write-Log -message ("{0} :: created new [{1}] section" -f $($MyInvocation.MyCommand.Name), $section) -severity 'DEBUG'
      } else {
        Write-Log -message ("{0} :: detected existing [{1}] section" -f $($MyInvocation.MyCommand.Name), $section) -severity 'DEBUG'
      }
      if (-not $config[$section].ContainsKey($key)) {
        try {
          $config[$section].Add($key, $value)
          $encoding = (Get-FileEncoding -path $file)
          Out-IniFile -InputObject $config -FilePath $file -Encoding $encoding -Force
          Write-Log -message ("{0} :: set: [{1}]/{2}, to: '{3}', in: {4}." -f $($MyInvocation.MyCommand.Name), $section, $key, $value, $file) -severity 'INFO'
        } catch {
          Write-Log -message ("{0} :: failed to set ini value. {1}" -f $($MyInvocation.MyCommand.Name), $_.Exception) -severity 'ERROR'
        }
      } else {
        Write-Log -message ("{0} :: detected key: {1} with value: '{2}'." -f $($MyInvocation.MyCommand.Name), $key, $config[$section][$key]) -severity 'DEBUG'
        if ($config[$section][$key] -ne $value) {
          try {
            $config[$section].Set_Item($key, $value)
            $encoding = (Get-FileEncoding -path $hgrc)
            Out-IniFile -InputObject $config -FilePath $hgrc -Encoding $encoding -Force
          Write-Log -message ("{0} :: set: [{1}]/{2}, to: '{3}', in: {4}." -f $($MyInvocation.MyCommand.Name), $section, $key, $value, $file) -severity 'INFO'
          } catch {
            Write-Log -message ("{0} :: failed to set ini value. {1}" -f $($MyInvocation.MyCommand.Name), $_.Exception) -severity 'ERROR'
          }
        }
      }
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

function Install-BundleClone {
  param (
    [string] $version = 'd1e664f1dc8d', # latest: 'default'
    [string] $url = ('https://hg.mozilla.org/hgcustom/version-control-tools/raw-file/{0}/hgext/bundleclone/__init__.py' -f $version),
    [string] $path = [IO.Path]::Combine([IO.Path]::Combine(('{0}\' -f $env:SystemDrive), 'mozilla-build'), 'hg'),
    [string] $filename = 'bundleclone.py'
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    if ((Test-Path ('{0}\Mercurial' -f $env:ProgramFiles)) -and !(Test-Path $path)) {
      Create-SymbolicLink -link $path -target ('{0}\Mercurial' -f $env:ProgramFiles)
    }
    if (Test-Path $path) {
      $target = ('{0}\{1}' -f $path, $filename)
      if (Test-Path $target) {
        Remove-Item -path $target -force
      }
      Write-Log -message ('installing bundleclone (version: {0}) to: {1}' -f $version, $target) -severity 'INFO'
      (New-Object Net.WebClient).DownloadFile($url, $target)
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

function Enable-BundleClone {
  param (
    [string] $hgrc = [IO.Path]::Combine($env:USERPROFILE, '.hgrc'),
    [string] $path = [IO.Path]::Combine([IO.Path]::Combine([IO.Path]::Combine(('{0}\' -f $env:SystemDrive), 'mozilla-build'), 'hg'), 'bundleclone.py'),
    [string] $domain = $env:USERDOMAIN
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    Set-IniValue -file $hgrc -section 'extensions' -key 'bundleclone' -value $path
    if ($domain.EndsWith("use1.mozilla.com")) {
      Set-IniValue -file $hgrc -section 'bundleclone' -key 'prefers' -value "ec2region=us-east-1, stream=revlogv1"
    }
    elseif ($domain.EndsWith("usw2.mozilla.com")) {
      Set-IniValue -file $hgrc -section 'bundleclone' -key 'prefers' -value "ec2region=us-west-2, stream=revlogv1"
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

function Install-Package {
  param (
    [string] $id,
    [string] $version,
    [string] $testPath
  )
  if (Test-Path $testPath) {
    Write-Log -message ("{0} :: {1} install skipped, {2} exists" -f $($MyInvocation.MyCommand.Name), $id, $testPath) -severity 'DEBUG'
    return $false
  }
  Write-Log -message ("{0} :: installing {1}" -f $($MyInvocation.MyCommand.Name), $id) -severity 'DEBUG'
  $cmdArgs = @('install', '-y', '--force', $id, '--version', $version)
  & 'choco' $cmdArgs
  $exitCode = $LastExitCode
  if (($?) -and (Test-Path $testPath)) {
    Write-Log -message ("{0} :: {1} install succeeded" -f $($MyInvocation.MyCommand.Name), $id) -severity 'INFO'
    return $true
  } else {
    Write-Log -message ("{0} :: {1} install failed with exit code: {2}" -f $($MyInvocation.MyCommand.Name), $id, $exitCode) -severity 'ERROR'
    return $false
  }
}

function Create-SymbolicLink {
  param (
    [string] $link,
    [string] $target
  )
  if (Test-Path $target -PathType Container) {
    Write-Log -message ("{0} :: creating directory symlink: {1}, pointing to: {2}" -f $($MyInvocation.MyCommand.Name), $link, $target) -severity 'INFO'
    $cmdArgs = @('/c', 'mklink', '/D', $link, $target)
  } else {
    Write-Log -message ("{0} :: creating file symlink: {1}, pointing to: {2}" -f $($MyInvocation.MyCommand.Name), $link, $target) -severity 'INFO'
    $cmdArgs = @('/c', 'mklink', $link, $target)
  }
  & 'cmd' $cmdArgs
}

function Rename-Admin {
  if ([ADSI]::Exists('WinNT://./Administrator')) {
    Write-Log -message ("{0} :: renaming administrator account" -f $($MyInvocation.MyCommand.Name)) -severity 'INFO'
    ([ADSI]"WinNT://./Administrator,user").PSBase.Rename("root")
  }
}

function Create-LocalUser {
  param (
    [string] $username = 'cltbld',
    [string] $password = $username,
    [string] $description = 'Mozilla Build'
  )
  try {
    $u = ([ADSI]"WinNT://.").Create("User", $username)
    $u.SetInfo()
    Write-Log -message ("{0} :: user: {1}, created" -f $($MyInvocation.MyCommand.Name), $username) -severity 'DEBUG'
    try {
      $u.SetPassword($password)
      $u.SetInfo()
      $u.Description = $description
      $u.SetInfo()
      Write-Log -message ("{0} :: password, description set for user: {1}" -f $($MyInvocation.MyCommand.Name), $username) -severity 'DEBUG'
    } catch {
      Write-Log -message ("{0} :: failed to set password, description for user: {1}, {2}" -f $($MyInvocation.MyCommand.Name), $username, $_.Exception) -severity 'ERROR'
    }
    Start-Sleep -s 2
    try {
      #$a = [ADSI]"WinNT://./Administrators,group"
      #$a.Add("WinNT://./$username,user")
      $netArgs = @('localgroup', 'Administrators', '/add', $username)
      & 'net' $netArgs
      Write-Log -message ("{0} :: user: {1}, with path: {2}, added to local admin group" -f $($MyInvocation.MyCommand.Name), $username, $u.Path) -severity 'DEBUG'
    } catch {
      Write-Log -message ("{0} :: failed to add user: {1}, with path: {2}, to local admin group. {3}" -f $($MyInvocation.MyCommand.Name), $username, $u.Path, $_.Exception) -severity 'ERROR'
    }
  } catch {
    Write-Log -message ("{0} :: failed to create user: {1}, {2}" -f $($MyInvocation.MyCommand.Name), $username, $_.Exception) -severity 'ERROR'
  }
}

function Create-Hgrc {
  param (
    [string] $hgrc = ('{0}\.hgrc' -f $env:UserProfile)
  )
  $config = @{
    'ui' = @{
      'username' = 'Mozilla Release Engineering <release@mozilla.com>';
      'traceback' = 'True'
    };
    'diff' = @{
      'git' = 'True';
      'showfunc' = 'True';
      'ignoreblanklines' = 'True'
    };
    'format' = @{
      'dotencode' = 'False'
    };
    'hostfingerprints' = @{
      'hg.mozilla.org' = 'af:27:b9:34:47:4e:e5:98:01:f6:83:2b:51:c9:aa:d8:df:fb:1a:27'
    };
    'extensions' = @{
      'share' = '';
      'rebase' = '';
      'mq' = '';
      'purge' = ''
    }
  }
  try {
    Out-IniFile -InputObject $config -FilePath $hgrc -Encoding "ASCII" -Force
    Write-Log -message ("{0} :: hgrc written to: {1}" -f $($MyInvocation.MyCommand.Name), $hgrc) -severity 'DEBUG'
  } catch {
    Write-Log -message ("{0} :: failed to write hgrc to: {1}, {2}" -f $($MyInvocation.MyCommand.Name), $hgrc, $_.Exception) -severity 'ERROR'
  }
}

function Install-BuildBot {
  param (
    [string] $version = '21b5392348c3', # latest: 'default'
    [string] $url = ('https://hg.mozilla.org/build/puppet/raw-file/{0}/modules/buildslave/files/runslave.py' -f $version),
    [string] $target = ('{0}\mozilla-build\buildbot.py' -f $env:SystemDrive)
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    try {
      if (Test-Path $target) {
        Write-Log -message ('{0} :: removing detected buildbot at: {1}' -f $($MyInvocation.MyCommand.Name), $target) -severity 'DEBUG'
        Remove-Item -path $target -force
      }
      (New-Object Net.WebClient).DownloadFile($url, $target)
      Write-Log -message ('{0} :: buildbot run script (version: {1}) installed to: {2}, from: {3}' -f $($MyInvocation.MyCommand.Name), $version, $target, $url) -severity 'DEBUG'
    } catch {
      Write-Log -message ("{0} :: failed to download buildbot from {1} to: {2}, {3}" -f $($MyInvocation.MyCommand.Name), $url, $target, $_.Exception) -severity 'ERROR'
    }
    try {
      Add-PathToPath -path ('{0}\mozilla-build\msys\bin' -f $env:SystemDrive) -target 'Machine'
      Add-PathToPath -path ('{0}\mozilla-build\python' -f $env:SystemDrive) -target 'Machine'
      Add-PathToPath -path ('{0}\mozilla-build\python\Scripts' -f $env:SystemDrive) -target 'Machine'

      if (!(Test-Path 'c:\mozilla-build\python\Scripts\twistd.py')) {
        $bashArgs = @('--login', '-c', '"pip install --trusted-host=puppetagain.pub.build.mozilla.org --find-links=http://puppetagain.pub.build.mozilla.org/data/python/packages/ --no-index --no-deps zope.interface==3.6.1 buildbot-slave==0.8.4-pre-moz8 buildbot==0.8.4-pre-moz8 Twisted==10.2.0 simplejson==2.1.3"')
        & 'bash' $bashArgs
        Write-Log -message ('{0} :: zope.interface, buildbot-slave, buildbot, Twisted and simplejson installed to /c/mozilla-build/python' -f $($MyInvocation.MyCommand.Name), $version, $target, $url) -severity 'DEBUG'
      }
      if (!(Test-Path 'c:\mozilla-build\python\Lib\site-packages\pywin32-218-py2.7-win32.egg' -PathType Container)) {
        $bashArgs = @('--login', '-c', '"easy_install.exe http://releng-puppet1.srv.releng.use1.mozilla.com/repos/EXEs/pywin32-218.win32-py2.7.exe"')
        & 'bash' $bashArgs
        Write-Log -message ('{0} :: pywin32 installed to /c/mozilla-build/python/Lib/site-packages/pywin32-218-py2.7-win32.egg' -f $($MyInvocation.MyCommand.Name), $version, $target, $url) -severity 'DEBUG'
      }
      
      Create-SymbolicLink -link ('{0}\mozilla-build\virtualenv.py' -f $env:SystemDrive) -target ('{0}\mozilla-build\python\Lib\site-packages\virtualenv.py' -f $env:SystemDrive)
      #Create-SymbolicLink -link ('{0}\mozilla-build\python\virtualenv.py' -f $env:SystemDrive) -target ('{0}\mozilla-build\python\Lib\site-packages\virtualenv.py' -f $env:SystemDrive)
    } catch {
      Write-Log -message ("{0} :: failed to install buildbot virtualenv. {1}" -f $($MyInvocation.MyCommand.Name), $_.Exception) -severity 'ERROR'
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

<# not used. buildbot is run from userdata as cltbld
function Enable-BuildBot {
  param (
    [string] $username = 'cltbld',
    [string] $target = ('{0}\Users\{1}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start-buildbot.bat' -f $env:SystemDrive, $username)
  )
  process {
    try {
      if (Test-Path $target) {
        Write-Log -message ('{0} :: removing detected buildbot start script at: {1}' -f $($MyInvocation.MyCommand.Name), $target) -severity 'DEBUG'
        Remove-Item -path $target -force
      }
      Set-Content -Path $target -Value ('bash --login -c "python /c/mozilla-build/buildbot.py"' -f $env:SystemDrive) -Force
      Write-Log -message ('{0} :: buildbot start script installed to : {1}' -f $($MyInvocation.MyCommand.Name), $target) -severity 'DEBUG'
    } catch {
      Write-Log -message ("{0} :: failed to install buildbot start script to: {1}" -f $($MyInvocation.MyCommand.Name), $target, $_.Exception) -severity 'ERROR'
    }
  }
}
#>

function Install-DirectX10 {
  param (
    [string] $url = 'http://download.microsoft.com/download/A/E/7/AE743F1F-632B-4809-87A9-AA1BB3458E31/DXSDK_Jun10.exe',
    [string] $target = ('{0}\DXSDK_Jun10.exe' -f $env:SystemDrive)
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    if (Test-Path ('{0}\Microsoft DirectX SDK (June 2010)\Utilities\bin\dx_setenv.cmd' -f ${env:ProgramFiles(x86)})) {
      Write-Log -message ('{0} ::DirectX install detected' -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
    } else {
      try {
        if (Test-Path $target) {
          Write-Log -message ('{0} :: removing detected installer at: {1}' -f $($MyInvocation.MyCommand.Name), $target) -severity 'DEBUG'
          Remove-Item -path $target -force
        }
        (New-Object Net.WebClient).DownloadFile($url, $target)
        Start-Process $target -ArgumentList "/U" -wait -NoNewWindow -PassThru -RedirectStandardOutput 'C:\log\directx-install-stdout.log' -RedirectStandardError 'C:\log\directx-install-stderr.log'
        Remove-Item -path $target -force
        Write-Log -message ('{0} ::DirectX installed, maybe' -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
      } catch {
        Write-Log -message ("{0} :: failed to install DirectX. {1}" -f $($MyInvocation.MyCommand.Name), $_.Exception) -severity 'ERROR'
      }
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
}

function Install-RelOpsPrerequisites {
  param (
    [string] $aggregator
  )
  Install-Package -id 'nxlog' -version '2.8.1248' -testPath ('{0}\nxlog\conf\nxlog.conf' -f ${env:ProgramFiles(x86)})
  Configure-NxLog -aggregator $aggregator
  Install-Package -id 'sublimetext3' -version '3.0.0.3083' -testPath ('{0}\Sublime Text 3\sublime_text.exe' -f $env:ProgramFiles)
  Install-Package -id 'sublimetext3.packagecontrol' -version '2.0.0.20140915' -testPath ('{0}\Sublime Text 3\Installed Packages\Package Control.sublime-package' -f $env:AppData)
  #Install-Package -id 'puppet' -version '3.7.4' -testPath ('{0}\Puppet Labs\Puppet\bin\puppet.bat' -f $env:ProgramFiles)
  #Install-Package -id 'puppet-agent' -version '1.2.4' -testPath ('{0}\Puppet Labs\Puppet\bin\puppet.bat' -f $env:ProgramFiles)
  #Install-Package -id 'git' -version '2.5.3' -testPath ('{0}\Git\usr\bin\bash.exe' -f $env:ProgramFiles)
  #$msys = ('{0}\Git\usr\bin' -f $env:ProgramFiles)
  #if ((Test-Path $msys) -and !$env:Path.Contains($msys)) {
  #  [Environment]::SetEnvironmentVariable("PATH", ('{0};{1}' -f $msys, $env:Path), "Machine")
  #}
}

function Test-Key {
  param (
    [string] $path,
    [string] $key
  )
  if(!(Test-Path $path)) { return $false }
  if ((Get-ItemProperty $path).$key -eq $null) { return $false }
  return $true
}

function Install-MozillaBuildAndPrerequisites {
  if (!(Test-Key "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v3.5" "Install")) {
    Add-WindowsFeature -Name 'NET-Framework-Core' -IncludeAllSubFeature # prerequisite for June 2010 DirectX SDK is to install ".NET Framework 3.5 (includes .NET 2.0 and 3.0)"
  }
  Install-DirectX10
  Install-Package -id 'visualstudiocommunity2013' -version '12.0.21005.1' -testPath ('{0}\Microsoft Visual Studio 12.0\Common7\IDE\devenv.exe' -f ${env:ProgramFiles(x86)})
  Install-Package -id 'windows-sdk-8.1' -version '8.100.26654.0' -testPath ('{0}\Microsoft Visual Studio 12.0\Common7\IDE\devenv.exe' -f ${env:ProgramFiles(x86)})
  if(Install-Package -id 'mozillabuild' -version '2.0.0' -testPath ('{0}\mozilla-build\yasm\yasm.exe' -f $env:SystemDrive)) {
    Create-SymbolicLink -link ('{0}\mozilla-build\python27' -f $env:SystemDrive) -target ('{0}\mozilla-build\python' -f $env:SystemDrive)
    if (!(Test-Path 'c:\mozilla-build\python\Lib\site-packages\pywin32-218-py2.7-win32.egg' -PathType Container)) {
      $bashArgs = @('--login', '-c', '"/c/mozilla-build/python/Scripts/easy_install.exe http://releng-puppet1.srv.releng.use1.mozilla.com/repos/EXEs/pywin32-218.win32-py2.7.exe"')
      & 'bash' $bashArgs
      Write-Log -message ('{0} :: pywin32 installed to /c/mozilla-build/python/Lib/site-packages/pywin32-218-py2.7-win32.egg' -f $($MyInvocation.MyCommand.Name), $version, $target, $url) -severity 'DEBUG'
    }
    $bashArgs = @('--login', '-c', '"/c/mozilla-build/python/Scripts/pip uninstall mercurial --yes"')
    & ('{0}\mozilla-build\msys\bin\bash.exe' -f $env:SystemDrive) $bashArgs
    foreach ($mbhg in @(('{0}\mozilla-build\python\Scripts\hg' -f $env:SystemDrive), ('{0}\mozilla-build\python\Scripts\hg.bat' -f $env:SystemDrive), ('{0}\mozilla-build\python\Scripts\hg.exe' -f $env:SystemDrive))) {
      if (Test-Path $mbhg) {
        Remove-Item $mbhg -force
      }
    }
  }
  if (Install-Package -id 'hg' -version '3.5.1' -testPath ('{0}\Mercurial\hg.exe' -f $env:ProgramFiles)) {
    Create-SymbolicLink -link ('{0}\mozilla-build\hg' -f $env:SystemDrive) -target ('{0}\Mercurial' -f $env:ProgramFiles)
  }
  Install-BundleClone
  Add-PathToPath -path ('{0}\mozilla-build\msys\bin' -f $env:SystemDrive)
  Add-PathToPath -path ('{0}\mozilla-build\python' -f $env:SystemDrive)
  Add-PathToPath -path ('{0}\mozilla-build\python\Scripts' -f $env:SystemDrive)
}

function Install-BasePrerequisites {
  param (
    [string] $aggregator = 'log-aggregator.srv.releng.use1.mozilla.com'
  )
  Write-Log -message ("{0} :: installing chocolatey" -f $($MyInvocation.MyCommand.Name)) -severity 'INFO'
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  Install-RelOpsPrerequisites -aggregator $aggregator
  Install-MozillaBuildAndPrerequisites
  Install-BuildBot
}

function Set-Timezone {
  param (
    [string] $timezone = 'Pacific Standard Time'
  )
  $a = @('/s', ('"{0}"' -f $timezone))
  & 'tzutil' $a
}

function Configure-NxLog {
  param (
    [string] $version = '12020ace67f4', # latest: 'default'
    [string] $url = ('https://hg.mozilla.org/build/puppet/raw-file/{0}/modules/nxlog/templates' -f $version), # latest: 'default'
    [string] $target = ('{0}\nxlog\conf' -f ${env:ProgramFiles(x86)}),
    [string[]] $files = @('nxlog.conf', 'nxlog_source_eventlog_win2008_ec2.conf', 'nxlog_route_eventlog_aggregator.conf', 'nxlog_target_aggregator.conf', 'nxlog_transform_syslog.conf'),
    [string] $aggregator
  )
  foreach ($file in $files) {
    $remote = ('{0}/{1}.erb' -f $url, $file)
    $local = ('{0}\{1}' -f $target, $file)
    try {
      (New-Object Net.WebClient).DownloadFile($remote, $local)
      Write-Log -message ("{0} :: downloaded: {1} from: {2}" -f $($MyInvocation.MyCommand.Name), $local, $remote) -severity 'DEBUG'
    }
    catch {
      Write-Log -message ("{0} :: failed to download: {1} from: {2}. {3}" -f $($MyInvocation.MyCommand.Name), $local, $remote, $_.Exception) -severity 'ERROR'
    }
  }
  Set-Aggregator -aggregator $aggregator
}

function Run-BuildBot {
  param (
    [string] $username = 'cltbld',
    [string] $password = $username
  )
  $lusers = (([ADSI]"WinNT://.").Children | Where { ($_.SchemaClassName -eq 'user') } | % { $_.name[0].ToString() } )
  if($lusers -NotContains $username) {
    Create-LocalUser -username $username -password $password
  } else {
    $u = ([ADSI]"WinNT://./$username,user")
    $u.SetPassword($password)
    $u.SetInfo()
    Write-Log -message ("{0} :: password changed for user: {1}" -f $($MyInvocation.MyCommand.Name), $username) -severity 'INFO'
  }
  Enable-PSRemoting -Force
  Set-Item wsman:\localhost\client\trustedhosts 'localhost' -Force
  Restart-Service WinRM
  $credential = New-Object Management.Automation.PSCredential ('.\{0}' -f $username), (ConvertTo-SecureString $password -AsPlainText -Force)
  try {
    Invoke-Command -ComputerName 'localhost' -Credential $credential -ScriptBlock {
      $hgrc = ('{0}\.hgrc' -f $env:UserProfile)
      Create-Hgrc -hgrc $hgrc
      if (Test-Path $hgrc) {
        Enable-BundleClone -hgrc $hgrc
      }
      
      $env:MOZBUILDDIR = ('{0}\mozilla-build' -f $env:SystemDrive)
      [Environment]::SetEnvironmentVariable("MOZBUILDDIR", $env:MOZBUILDDIR, 'User')
      
      $env:MOZILLABUILD = ('{0}\mozilla-build' -f $env:SystemDrive)
      [Environment]::SetEnvironmentVariable("MOZILLABUILD", $env:MOZILLABUILD, 'User')
      
      $env:MOZ_TOOLS = ('{0}\moztools-x64' -f $env:MOZILLABUILD)
      [Environment]::SetEnvironmentVariable("MOZ_TOOLS", $env:MOZ_TOOLS, 'User')

      Add-PathToPath -path ('{0}\bin' -f $env:MOZ_TOOLS) -target 'User'
      
      $env:IDLEIZER_HALT_ON_IDLE = 'true'
      [Environment]::SetEnvironmentVariable("IDLEIZER_HALT_ON_IDLE", $env:IDLEIZER_HALT_ON_IDLE, 'User')

      Add-PathToPath -path ('{0}\mozilla-build\msys\bin' -f $env:SystemDrive) -target 'User'
      Add-PathToPath -path ('{0}\mozilla-build\python' -f $env:SystemDrive) -target 'User'
      Add-PathToPath -path ('{0}\mozilla-build\python\Scripts' -f $env:SystemDrive) -target 'User'

      Write-Log -message ("{0} :: starting buildbot" -f $($MyInvocation.MyCommand.Name)) -severity 'INFO'
      $bashArgs = @('--login', '-c', '"python /c/mozilla-build/buildbot.py --twistd-cmd /c/mozilla-build/python/Scripts/twistd.py"')
      & 'bash' $bashArgs
      Write-Log -message ("{0} :: buildbot started" -f $($MyInvocation.MyCommand.Name)) -severity 'INFO'
    }
  }
  catch {
    Write-Log -message ("{0} :: failed to start buildbot. {1}" -f $($MyInvocation.MyCommand.Name), $_.Exception) -severity 'ERROR'
  }
}

function Add-PathToPath {
  param (
    [string] $path,
    [string] $target = 'Machine'
  )
  $paths = @()
  ($env:Path.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries) | Get-Unique) | %{ $paths += $_.TrimEnd('\') }
  $paths = $paths | Get-Unique
  if ($paths -Contains $path) {
    Write-Log -message ("{0} :: {1} detected in current PATH" -f $($MyInvocation.MyCommand.Name), $path) -severity 'DEBUG'
  } else {
    $paths += $path
    Write-Log -message ("{0} :: {1} added to PATH at {2} level" -f $($MyInvocation.MyCommand.Name), $path, $target) -severity 'INFO'
  }
  $env:Path = [string]::Join(';', $paths)
  [Environment]::SetEnvironmentVariable("PATH", $env:Path, $target)
}

function New-SWRandomPassword {
  <#
  .Synopsis
     Generates one or more complex passwords designed to fulfill the requirements for Active Directory
  .DESCRIPTION
     Generates one or more complex passwords designed to fulfill the requirements for Active Directory
  .EXAMPLE
     New-SWRandomPassword
     C&3SX6Kn

     Will generate one password with a length between 8  and 12 chars.
  .EXAMPLE
     New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
     7d&5cnaB
     !Bh776T"Fw
     9"C"RxKcY
     %mtM7#9LQ9h

     Will generate four passwords, each with a length of between 8 and 12 chars.
  .EXAMPLE
     New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
     3ABa

     Generates a password with a length of 4 containing atleast one char from each InputString
  .EXAMPLE
     New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
     3ABa

     Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
     the string specified with the parameter FirstChar
  .OUTPUTS
     [String]
  .NOTES
     Written by Simon Wåhlin, blog.simonw.se
     I take no responsibility for any issues caused by this script.
  .FUNCTIONALITY
     Generates random passwords
  .LINK
     http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
 
  #>
  [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
  [OutputType([String])]
  Param
  (
    # Specifies minimum password length
    [Parameter(Mandatory=$false,
               ParameterSetName='RandomLength')]
    [ValidateScript({$_ -gt 0})]
    [Alias('Min')] 
    [int]$MinPasswordLength = 8,
    
    # Specifies maximum password length
    [Parameter(Mandatory=$false,
               ParameterSetName='RandomLength')]
    [ValidateScript({
            if($_ -ge $MinPasswordLength){$true}
            else{Throw 'Max value cannot be lesser than min value.'}})]
    [Alias('Max')]
    [int]$MaxPasswordLength = 12,

    # Specifies a fixed password length
    [Parameter(Mandatory=$false,
               ParameterSetName='FixedLength')]
    [ValidateRange(1,2147483647)]
    [int]$PasswordLength = 8,
    
    # Specifies an array of strings containing charactergroups from which the password will be generated.
    # At least one char from each group (string) will be used.
    [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&'),

    # Specifies a string containing a character group from which the first character in the password will be generated.
    # Useful for systems which requires first char in password to be alphabetic.
    [String] $FirstChar,
    
    # Specifies number of passwords to generate.
    [ValidateRange(1,2147483647)]
    [int]$Count = 1
  )
  Begin {
    Function Get-Seed{
      # Generate a seed for randomization
      $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
      $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
      $Random.GetBytes($RandomBytes)
      [BitConverter]::ToUInt32($RandomBytes, 0)
    }
  }
  Process {
    For($iteration = 1;$iteration -le $Count; $iteration++){
      $Password = @{}
      # Create char arrays containing groups of possible chars
      [char[][]]$CharGroups = $InputStrings

      # Create char array containing all chars
      $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

      # Set password length
      if($PSCmdlet.ParameterSetName -eq 'RandomLength')
      {
        if($MinPasswordLength -eq $MaxPasswordLength) {
          # If password length is set, use set length
          $PasswordLength = $MinPasswordLength
        }
        else {
          # Otherwise randomize password length
          $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
        }
      }

      # If FirstChar is defined, randomize first char in password from that string.
      if($PSBoundParameters.ContainsKey('FirstChar')){
        $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
      }
      # Randomize one char from each group
      Foreach($Group in $CharGroups) {
        if($Password.Count -lt $PasswordLength) {
          $Index = Get-Seed
          While ($Password.ContainsKey($Index)){
            $Index = Get-Seed                        
          }
          $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
        }
      }

      # Fill out with chars from $AllChars
      for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
        $Index = Get-Seed
        While ($Password.ContainsKey($Index)){
          $Index = Get-Seed                        
        }
        $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
      }
      Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
    }
  }
}