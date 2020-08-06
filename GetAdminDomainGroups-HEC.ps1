####################################################
#
# Active Directory Admin Groups
# Version: 1.3
#
####################################################

#ipmo ActiveDirectory;

################# Variables #####################

# privileged groups
$privGroups = "Domain Admins","Enterprise Admins","Account Operators","Backup Operators","Administrators","DNSAdmins","Group Policy Creator Owners","Schema Admins","Incoming Forest Trust Builders","Network Configuration Operators","Remote Desktop Users","Server Operators"

# list of properties to retrieve from active directory
$props = "name","sAMAccountName","description","objectCategory","objectClass","objectSID","distinguishedName","managedBy","mail","member","memberOf","whencreated","whenchanged"

# script path
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# required for file logging
$logStarted = $false

# required for hec_logging
$token = "HEC_TOKEN"
$server = "SERVER_IP"
$port = 8088
$sourcetype = "hec:ad_admin_groups"

# log type (file or hec)
$log_type = "hec"

# use ldaps for queries
$enable_ldaps = $true

################# Variables #####################

############ SSL (Ignore SSL Check) #############

# only required if Splunk is using self-signed or untrusted certificate
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
[ServerCertificateValidationCallback]::Ignore()

############ SSL (Ignore SSL Check) #############

############ User Account Control Enum ############

 enum UserAccountControl{
	SCRIPT = 1
	ACCOUNTDISABLE = 2
	BIT_02 =  4
	HOMEDIR_REQUIRED = 8
	LOCKEDOUT = 16
	PASSWD_NOTREQD = 32
	PASSWD_CANT_CHANGE = 64
	ENCRYPTED_TEXT_PWD_ALLOWED = 128
	TEMP_DUPLICATE_ACCOUNT = 256
	NORMAL_ACCOUNT = 512
	BIT_10 = 1024
	INTERDOMAIN_TRUST_ACCOUNT = 2048
	WORKSTATION_TRUST_ACCOUNT = 4096
	SERVER_TRUST_ACCOUNT = 8192
	BIT_14 = 16384
	BIT_15 = 32768
	DONT_EXPIRE_PASSWORD = 65536
	MNS_LOGON_ACCOUNT = 131072
	SMARTCARD_REQUIRED = 262144
	TRUSTED_FOR_DELEGATION = 524288
	NOT_DELEGATED = 1048576
	USE_DES_KEY_ONLY = 2097152
	DONT_REQ_PREAUTH = 4194304
	PASSWORD_EXPIRED = 8388608
	TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216
	PARTIAL_SECRETS_ACCOUNT = 67108864
}

############ User Account Control Enum ############

################# Functions #####################

function file_log($logLine){
    if(${script:logStarted} -eq $false){
        Remove-Item -Path ${script:logFile} -Force -ErrorAction Ignore
        $script:logStarted = $true
    }

    # for array we split and write each
    if($logLine -is [array]){
        $logLine | % {
            $event = $_ | ConvertTo-Json -Compress
            $event | Out-File ${script:logFile} -Append
        }
    }else{
        $event = $logLine | ConvertTo-Json -Compress
        $event | Out-File ${script:logFile} -Append
    }
    
}

function hec_log($logLine){
    $url = "https://${script:server}:${script:port}/services/collector/event"
    $header = @{Authorization = "Splunk ${script:token}"}
    
    # for array we split and send each
    if($logLine -is [array]){
        $logLine | % {
            $event = @{ 
                source = $sourcetype
                sourcetype = $sourcetype
                event = $_ 
            } | ConvertTo-Json -Compress
            $result = Invoke-RestMethod -Method Post -Uri $url -Headers $header -Body $event
        }
    }else{
        $event = @{ 
            source = $sourcetype
            sourcetype = $sourcetype
            event = $logLine 
        } | ConvertTo-Json -Compress
        $result = Invoke-RestMethod -Method Post -Uri $url -Headers $header -Body $event
    }
}

function Get-DomainAdminGroups ($domainObj)
{
    $ncname =  $domainObj.properties.ncname[0]
    $netbiosname = $domainObj.properties.netbiosname[0]
    $dnsroot =  $domainObj.properties.dnsroot[0]

    $groupFilter = "(cn=" + ($privGroups -join ")(cn=") + ")"
    
    # connect to the domain
    $root = [ADSI]"LDAP://${dnsroot}:${ldap_port}/$ncname"
    $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
    $searcher.pagesize = 1000
    $searcher.cacheresults =$false
    $searcher.filter = "(&(objectClass=group)(|$groupFilter))"
    $objects = $searcher.findall()

    $count = 0
    
    $sw = [system.diagnostics.stopwatch]::startnew()

    # enumerate the object
    foreach($i in $objects)
    {
        #New-Object PSObject -Prop (@{'rootgroup'=$rootGroup; 'rootdn'=$rootDN;'membergroup'= $Member.Properties['name'].ToString();'membergroupdn'=$Member.Properties['distinguishedName'].ToString() }) | select-object *
        $obj = New-Object PSObject
        $ldapPath = $i.path.ToString().Substring($i.path.ToString().IndexOf("/",7)+1).Replace("/", "\/").Replace("\\/", "\/")
        $rootGroup = $i.Properties['name'][0].ToString()
        $rootDN = $i.Properties['distinguishedName'][0].ToString()
        
        $rootSID = (New-Object System.Security.Principal.SecurityIdentifier($i.Properties['objectsid'][0],0)).Value
        Get-ADNestedGroups -dnsroot $dnsroot -rootGroup $rootGroup -rootDN $rootDN -rootSID $rootSID -ldapPath $ldapPath -Path $rootGroup
        $count ++
    }

    write-output $sw.elapsed.totalmilliseconds;
    write-output ("Found {0} objects." -f $count)
}

function Get-ADNestedGroups {
    [cmdletbinding()]
    param (
        [String] $dnsroot,
        [String] $rootGroup,
        [String] $rootDN,
        [String] $rootSID,
        [String] $ldapPath,
        [String] $Path
    )
    $domains_local = $AdSearcher.FindAll()
    $netbiosname = $domainObj.properties.netbiosname[0]

    $g = [adsi]"LDAP://${dnsroot}:${ldap_port}/$ldapPath"
    $g.Member | % {
        $ldapPath = $_.ToString().Substring($_.ToString().IndexOf("/",7)+1).Replace("/", "\/").Replace("\\/", "\/")
        
        $obj = @{}
        $obj.Add("date", $(Get-Date -format o))
        $obj.Add("taskid", [string]$guid)
        $obj.Add("path", $ldapPath)

        $c = [adsi]"LDAP://${dnsroot}:${ldap_port}/$ldapPath"
        
        foreach($domain in $domains_local){
            if(("{0}" -f $c.properties["distinguishedname"][0]).EndsWith($domain.properties.ncname[0])){
                $groupdomain = $domain.properties.name[0]
            }
        }

        $member = @{}
        $member.Add("domain", $groupdomain)

        foreach($name in $props) {
            $name = $name.ToString().ToLower()
            
            if(($c.Properties -eq $null) -or ($c.Properties -ne $null -and $c.Properties.contains($name) -eq $false) -or ($c.Properties -ne $null -and $c.Properties.contains($name) -eq $true -and $c.Properties[$name].Value -eq $null)){
                $value = ""
            }elseif($name -eq "lastlogontimestamp" -or $name -eq "pwdlastset" -or $name -eq "accountexpires"){
                try{
                    if($c.properties.$name -ne $null){
                        $int64 = $c.ConvertLargeIntegerToInt64($c.properties.$name[0])
                        if($int64 -ne 9223372036854775807 -and $int64 -ne 0){
                            $value = [DateTime]::FromFileTime($c.ConvertLargeIntegerToInt64($c.properties.$name[0])).ToString('o')
                        }else{
                            $value = "0"
                        }
                    }else{
                        $value = $null
                    }
                }catch{
                    write-output "ERROR: Failed to process - $name"
                }
            }elseif($name -eq "useraccountcontrol"){
                $value = @()
                [System.Enum]::GetValues([UserAccountControl]) | % {
                    if ($c.properties.userAccountControl[0] -band [int]$_){
                         $value =  $value + [string]$_
                    }
                }
            }elseif($name -eq "operatingsystem"){
                $value = $c.properties[$name].Value -replace "\xAE", ''; 
            }elseif($name -eq "objectsid"){
                $value = (New-Object System.Security.Principal.SecurityIdentifier($c.properties[$name].Value,0)).Value
                $obj.Add("memberid",$value)
            }elseif($name -eq "userworkstations"){
                $value = $("{0}" -f $c.properties[$name][0])
            }elseif($name -eq "whencreated" -or $name -eq "whenchanged"){
                $value = get-date $c.properties[$name].Value -format o
            }elseif($name -eq "primarygroupid"){
                $value = $c.properties.primarygroupid.Value
                if($value -ne $null){
                    # add primary group sid
                    $primaryGroupID = $c.properties.primarygroupid.Value
                    $objectsid = (New-Object System.Security.Principal.SecurityIdentifier($root.properties["objectsid"].Value,0)).ToString()
                    $sb = New-Object -TypeName "System.Text.StringBuilder";

                    $sidArr = $objectsid.Split("-")
                    for($i = 0; $i -lt $sidArr.Length; $i++){
                        [void]$sb.Append($sidArr[$i])
                        [void]$sb.Append("-")
                    }
                    [void]$sb.Append($primaryGroupID.ToString())
    
                    # find primary group sid and name
                    $member.Add("primarygroupsid", $($sb.ToString()))
        
                    $primarysidobj = [ADSI]("LDAP://${dnsroot}:${ldap_port}/<SID={0}>" -f $sb.ToString())
                    $primarygroupobj = [ADSI]$primarysidobj.path
                    $member.Add("primarygroupname", $primarygroupobj.properties["name"].Value)
                }
            }elseif($name -eq "usercertificate"){
                $value = @()
                
                # add certificate info
                $cert_info = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                foreach ($i in ($c.properties["userCertificate"])) {
                    $cert_info.import([byte[]]($i))
                    $value = $value + $cert_info
                    break
                }
                
            }else{
                $value = $c.properties[$name].Value -replace "““","\""" -replace "””","\"""
            }
            
            $member.Add($name, $value)
        }

        # add domain
        $obj.Add("domain", $netbiosname)

        # add root group properties
        $obj.Add("rootgroup",$rootgroup)
        $obj.Add("rootdn",$rootdn)
        $obj.Add("rootsid",$rootsid)
        $obj.Add("member",$member)
        $obj.Add("rootpath",$Path)

        # output the result to file or hec
        if($log_type -eq "hec"){ hec_log ($obj) } else { file_log($obj) }
        [System.GC]::Collect()
            
        Get-ADNestedGroups -dnsroot $dnsroot -rootGroup $rootGroup -rootDN $rootDN -rootSID $rootSID -ldapPath $ldapPath -Path ("{0}\{1}" -f $Path, $c.properties['Name'].Value)
      
    }
              
}

################# Functions #####################

################# Script #####################

write-output "Starting script..."

$ldap_port = if($enable_ldaps -eq $true) { "636" }else{ "389" }
$dnsroot = $(Get-ADRootDSE).dnsHostName
$guid = [guid]::NewGuid()
$Root = [ADSI]"LDAP://${dnsroot}:${ldap_port}/RootDSE"
$oForestConfig = $Root.Get("configurationNamingContext")
$oSearchRoot = [ADSI]("LDAP://${dnsroot}:${ldap_port}/CN=Partitions," + $oForestConfig)
$AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
$AdSearcher.SearchRoot = $oSearchRoot
$domains = $AdSearcher.FindAll()
$domains | % {
    if($_.properties.netbiosname[0] -ne $null){
        write-output ("Enumerating domain: {0}" -f $_.properties.netbiosname[0])
        Get-DomainAdminGroups $_
        write-output "Domain processing complete."
    }
}
write-output "Script complete."

################# Script #####################