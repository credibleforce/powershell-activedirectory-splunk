####################################################
#
# Active Directory Computers
# Version: 1.1
#
####################################################

#ipmo ActiveDirectory;

################# Variables #####################

# list of properties to retrieve from active directory
$props = "name","sAMAccountName","description","objectCategory","objectClass","objectSID","distinguishedName","operatingSystem","operatingSystemServicePack","operatingSystemVersion","useraccountcontrol","pwdLastSet","memberOf","accountexpires","whenChanged","whenCreated","lastlogontimestamp","dNSHostName","usercertificate"

# script path
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# required for file logging
$logStarted = $false
$logFile = "$PSScriptRoot\getdomaincomputers_output.txt"

# required for hec_logging
$token = "HEC_TOKEN"
$server = "SERVER_IP"
$port = 8088
$sourcetype = "hec:ad_computers"

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

function GetDomainComputers ($domainObj)
{
    $ncname =  $domainObj.properties.ncname[0]
    $netbiosname = $domainObj.properties.netbiosname[0]
    $dnsroot =  $domainObj.properties.dnsroot[0]

    # connect to the domain
    $root = [ADSI]"LDAP://${dnsroot}:${ldap_port}/$ncname"
    $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
    $searcher.pagesize = 1000
    $searcher.cacheresults =$false
    $searcher.filter = "(&(objectCategory=computer))"
    foreach($name in $props){
        $n = $searcher.PropertiesToLoad.Add($name)
    }
    $objects = $searcher.FindAll()
    $count = 0

    $sw = [system.diagnostics.stopwatch]::startnew()
    $bulk = @()
    # enumerate the object
    foreach($i in $objects)
    {
        $count ++
        $ldapPath = $i.path.ToString().Substring($i.path.ToString().IndexOf("/",7)+1).Replace("/", "\/").Replace("\\/", "\/")
        
        $obj = @{}
        $obj.Add("date", $(Get-Date -format o))
        $obj.Add("item", $count)
        $obj.Add("taskid", [string]$guid)
        $obj.Add("path", $ldapPath)

        #write-output ("Processing node: {0}" -f  $ldapPath)
        
        $c = [adsi]"LDAP://${dnsroot}:${ldap_port}/$ldapPath"
        #write-output ("Found node: {0}" -f $c.path)

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
                    $obj.Add("primarygroupsid", $($sb.ToString()))
        
                    $primarysidobj = [ADSI]("LDAP://${dnsroot}:${ldap_port}/<SID={0}>" -f $sb.ToString())
                    $primarygroupobj = [ADSI]$primarysidobj.path
                    $obj.Add("primarygroupname", $primarygroupobj.properties["name"].Value)
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
            
            $obj.Add($name, $value)
        }

        # add domain
        $obj.Add("domain", $netbiosname)

        # add parentou
        $parentou = $c.properties["distinguishedName"][0].SubString($c.properties["distinguishedName"][0].indexof(',OU=')+1)
        $obj.Add("parentou", $parentou)
        
        $bulk = $bulk + $obj

        # output the result to file or hec
        
        # only post every 100
        if($count%100 -eq 0) {
            if($log_type -eq "hec"){ hec_log ($bulk) } else { file_log($bulk) }
            $bulk = @()
            [System.GC]::Collect()
        }
    }

    # for any remaining items not captures in bulk post
    if($bulk.Length -gt 0){
        if($log_type -eq "hec"){ hec_log ($bulk) } else { file_log($bulk) }
        $bulk = @()
        [System.GC]::Collect()
    }

    write-output $sw.elapsed.totalmilliseconds;
    write-output ("Found {0} objects." -f $count)
}

################# Functions #####################


################# Script #####################

write-output "Starting script..."

$ldap_port = if($enable_ldaps -eq $true) { "636" }else{ "389" }
$dnsroot = ([ADSI]"LDAP://rootdse").dnsHostName
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
        GetDomainComputers $_
        write-output "Domain processing complete."
    }
}

################# Script #####################



