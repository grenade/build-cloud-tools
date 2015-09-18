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
  $formattedMessage = ('{0} [{1}] {2}' -f [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss"), $severity, $message)
  Add-Content -Path $path -Value $formattedMessage
  if ($env:OutputToConsole -eq 'true') {
    switch ($severity) 
    {
      'DEBUG' { Write-Host -Object $formattedMessage -ForegroundColor 'DarkGray' }
      'ERROR' { Write-Host -Object $formattedMessage -ForegroundColor 'Red' }
      default { Write-Host -Object $formattedMessage }
    }
  }
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
  Send-MailMessage -To $to -Subject $subject -Body ([IO.File]::ReadAllText($logfile)) -SmtpServer $smtpServer -From $from
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
  param (
    [string] $ec2SettingsFile = "C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"
  )
  $modified = $false;
  [xml]$xml = (Get-Content $ec2SettingsFile)
  foreach ($plugin in $xml.DocumentElement.Plugins.Plugin) {
    Write-Log -message ('plugin state of {0} read as: {1}, in: {2}' -f $plugin.Name, $plugin.State, $ec2SettingsFile) -severity 'DEBUG'
    if ($plugin.Name -eq "Ec2HandleUserData") {
      if ($plugin.State -ne "Enabled") {
        Write-Log -message ('changing state of Ec2HandleUserData plugin from: {0} to: Enabled, in: {1}' -f $plugin.State, $ec2SettingsFile) -severity 'INFO'
        $plugin.State = "Enabled"
        $modified = $true;
      }
    }
  }
  if ($modified) {
    Write-Log -message ('granting full access to: System, on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
    $icaclsArgs = @($ec2SettingsFile, '/grant', 'System:F')
    & 'icacls' $icaclsArgs
    $xml.Save($ec2SettingsFile)
  }
  Write-Log -message ('granting read access to: Everyone, on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
  $icaclsArgs = @($ec2SettingsFile, '/grant', 'Everyone:R')
  & 'icacls' $icaclsArgs
  Write-Log -message ('removing all inherited permissions on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
  $icaclsArgs = @($ec2SettingsFile, '/inheritance:r')
  & 'icacls' $icaclsArgs
  Write-Log -message ('removing access for: root, on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
  $icaclsArgs = @($ec2SettingsFile, '/remove:g', 'root')
  & 'icacls' $icaclsArgs
  Write-Log -message ('removing access for: Administrators, on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
  $icaclsArgs = @($ec2SettingsFile, '/remove:g', 'Administrators')
  & 'icacls' $icaclsArgs
  Write-Log -message ('removing access for: Users, on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
  $icaclsArgs = @($ec2SettingsFile, '/remove:g', 'Users')
  & 'icacls' $icaclsArgs
  Write-Log -message ('removing access for: System, on: {0}' -f $ec2SettingsFile) -severity 'DEBUG'
  $icaclsArgs = @($ec2SettingsFile, '/remove:g', 'System')
  & 'icacls' $icaclsArgs
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
  Write-Log -message 'deleting RunPuppet scheduled task' -severity 'INFO'
  $schtasksArgs = @('/delete', '/tn', 'RunPuppet', '/f')
  & 'schtasks' $schtasksArgs
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
    [string] $hostname,
    [string] $domain,
    [string] $puppetServer = 'puppet',
    [string] $logdest
  )
  Write-Log -message 'setting environment variables' -severity 'INFO'
  [Environment]::SetEnvironmentVariable("FACTER_domain", "$domain", "Process")
  [Environment]::SetEnvironmentVariable("FACTER_hostname", "$hostname", "Process")
  [Environment]::SetEnvironmentVariable("FACTER_fqdn", ("$hostname.$domain"), "Process")
  [Environment]::SetEnvironmentVariable("COMPUTERNAME", "$hostname", "Machine")
  [Environment]::SetEnvironmentVariable("USERDOMAIN", "$domain", "Machine")

  Write-Log -message 'running puppetization script' -severity 'INFO'
  #todo: log and mail output from vbs script
  cscript.exe ('{0}\Puppetlabs\puppet\var\puppettize_TEMP.vbs' -f $env:ProgramData)
  
  Write-Log -message ('running puppet agent, logging to: {0}' -f $logdest) -severity 'INFO'
  $puppetArgs = @('agent', '--test', '--detailed-exitcodes', '--server', $puppetServer, '--logdest', $logdest)
  & 'puppet' $puppetArgs

  Write-Log -message 'deleting RunPuppet scheduled task (again)' -severity 'INFO'
  $schtasksArgs = @('/delete', '/tn', 'RunPuppet', '/f')
  & 'schtasks' $schtasksArgs
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
  $primaryDnsSuffix = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain")."NV Domain"
  if ("$domainExpected" -ieq "$primaryDnsSuffix") {
    return $true
  } else {
    Write-Log -message ('nv domain registry key: {0}, expected: {1}' -f $primaryDnsSuffix, $domainExpected) -severity 'DEBUG'
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
    (Get-Content $conf) | 
      Foreach-Object { $_ -replace "(Host [^ ]*)", "Host $aggregator" } | 
        Set-Content $conf
    Restart-Service nxlog
    Write-Log -message "log aggregator set to: $aggregator" -severity 'INFO'
  }
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
  Write-Log -message 'flushing the Windows EventLog' -severity 'INFO'
  wevtutil el | % { wevtutil cl $_ }
}

function Run-StagingHacks {
  $hgrc = 'C:\Users\cltbld\.hgrc'
  if (Test-Path $hgrc) {
    Install-Mercurial
    Install-BundleClone
    Enable-BundleClone -hgrc $hgrc
  }
}

function Install-Mercurial {
  param (
    [string] $url = 'http://mercurial.selenic.com/release/windows/Mercurial-3.5.1-x64.exe',
    [string] $installer = [IO.Path]::Combine($env:TEMP, $url.Substring($url.LastIndexOf('/') + 1)),
    [string] $path = [IO.Path]::Combine([IO.Path]::Combine(('{0}\' -f $env:SystemDrive), 'mozilla-build'), 'hg'),
    [string] $log = [IO.Path]::Combine([IO.Path]::Combine(('{0}\' -f $env:SystemDrive), 'log'), 'hg-install.log')
  )
  (New-Object Net.WebClient).DownloadFile($url, $installer)
  $installArgs = @('/SP-', '/VerySilent', '/SUPPRESSMSGBOXES', ('/DIR={0}' -f $path), ('/LOG={0}' -f $log))
  & $installer $installArgs
}

function Install-BundleClone {
  param (
    [string] $url = 'https://hg.mozilla.org/hgcustom/version-control-tools/raw-file/default/hgext/bundleclone/__init__.py',
    [string] $path = [IO.Path]::Combine([IO.Path]::Combine(('{0}\' -f $env:SystemDrive), 'mozilla-build'), 'hg'),
    [string] $filename = 'bundleclone.py'
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    if (Test-Path $path) {
      $target = [IO.Path]::Combine($path, $filename)
      if (Test-Path $target) {
        Remove-Item -path $target -force
      }
      Write-Log -message ('installing latest bundleclone to: {0}' -f $target) -severity 'INFO'
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

function Disable-BundleClone {
  param (
    [string] $hgrc = [IO.Path]::Combine($env:USERPROFILE, '.hgrc')
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    Unset-IniValue -file $hgrc -section 'extensions' -key 'bundleclone'
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
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
    if (Test-Path $hgrc) {
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

function Unset-IniValue {
  param (
    [string] $file,
    [string] $section,
    [string] $key
  )
  begin {
    Write-Log -message ("{0} :: Function started" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
  }
  process {
    if (Test-Path $file) {
      Write-Log -message ("{0} :: detected ini file at: {1}" -f $($MyInvocation.MyCommand.Name), $file) -severity 'DEBUG'
      $config = Get-IniContent $file
      if ($config.ContainsKey($section)) {
        Write-Log -message ("{0} :: detected section: [{1}]." -f $($MyInvocation.MyCommand.Name), $section) -severity 'DEBUG'
        if ($config[$section].ContainsKey($key)) {
          Write-Log -message ("{0} :: detected key: {1}." -f $($MyInvocation.MyCommand.Name), $key) -severity 'DEBUG'
          try {
            $config[$section].Remove($key)
            $encoding = (Get-FileEncoding -path $file)
            Out-IniFile -InputObject $config -FilePath $file -Encoding $encoding -Force
          } catch {
            Write-Log -message ("{0} :: failed to unset ini value. {1}" -f $($MyInvocation.MyCommand.Name), $_.Exception) -severity 'ERROR'
          }
        }
      }
    }
  }
  end {
    Write-Log -message ("{0} :: Function ended" -f $($MyInvocation.MyCommand.Name)) -severity 'DEBUG'
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