param([string]$global:strEventUser, [string]$global:strCallingStation)
$ErrorActionPreference = "Stop"

$global:strVersion = "5.8ps"

$global:aClientIPs = @()
$global:aExclusions = @()
$global:aDHCPServers = @()
[string]$global:strDomain = ""
[string]$global:strLogPath = ""
[string]$global:strAgentServer = ""
[string]$global:strAgentPort = ""
[string]$global:strLogFormat = ""
[string]$global:strVsys = ""
[string]$global:strAPIKey = ""
[string]$global:blnAgent = ""
[string]$global:strTimeout = ""
[string]$global:strDebug = ""
[string]$global:strPostAddr = ""
[string]$global:strProxy = ""
[string]$global:blnMultipass = ""
[xml]$global:cfgXML = $null

Function LoadConfig
{
	$wlcs= $global:cfgXML.SelectNodes("/useridscriptconfig/wireless-lan-controllers")
	foreach ($wlc in $wlcs) {
		$global:aClientIPs += $wlc.get_InnerXML()
	}
	$global:strDomain = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Domain").get_InnerXML()
	$global:strLogPath = $global:cfgXML.SelectSingleNode("/useridscriptconfig/LogPath").get_InnerXML()
	$global:strAgentServer = $global:cfgXML.SelectSingleNode("/useridscriptconfig/AgentServer").get_InnerXML()
	$global:strAgentPort = $global:cfgXML.SelectSingleNode("/useridscriptconfig/AgentPort").get_InnerXML()
	$global:strLogFormat = $global:cfgXML.SelectSingleNode("/useridscriptconfig/LogFormat").get_InnerXML()
	$DHCPServers = $global:cfgXML.SelectNodes("/useridscriptconfig/DHCPServer")
	foreach ($DHCPServer in $DHCPServers) {
		$global:aDHCPServers += $DHCPServer.get_InnerXML()
	}
	$global:strVsys = $global:cfgXML.SelectSingleNode("/useridscriptconfig/VSYS").get_InnerXML()
	$global:strAPIKey = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Key").get_InnerXML()
	$global:blnAgent = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Agent").get_InnerXML()
	$global:strTimeout = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Timeout").get_InnerXML()
	$global:strDebug = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Debug").get_InnerXML()
	$global:strPostAddr = $global:cfgXML.SelectSingleNode("/useridscriptconfig/PostAddr").get_InnerXML()
	$global:strProxy = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Proxy").get_InnerXML()
	$global:blnMultipass = $global:cfgXML.SelectSingleNode("/useridscriptconfig/Multipass").get_InnerXML()
}

Function CreateDefaultConfig
{
	$XmlWriter = New-Object System.XMl.XmlTextWriter("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml",$Null)
	$XmlWriter.Formatting = 'Indented'
	$XmlWriter.Indentation = 1
	$XmlWriter.IndentChar = "`t"
	$XmlWriter.WriteStartDocument()
	$XmlWriter.WriteStartElement('useridscriptconfig')
	$XmlWriter.WriteStartElement('wireless-lan-controllers')
	$XmlWriter.WriteElementString('wlc',"1.1.1.1")
	$XmlWriter.WriteEndElement()
	$XmlWriter.WriteEndElement()
	$XmlWriter.WriteElementString('Domain',$ENV:USERDOMAIN)
	$XmlWriter.WriteElementString('LogPath',"C:\Windows\System32\LogFiles\")
	$XmlWriter.WriteElementString('LogFormat',"DHCP")
	$XmlWriter.WriteElementString('AgentServer',"127.0.0.1")
	$XmlWriter.WriteElementString('AgentPort',"5006")
	$XmlWriter.WriteElementString('Debug',"0")
	$XmlWriter.WriteElementString('DHCP',$ENV:COMPUTERNAME)
	$XmlWriter.WriteElementString('Agent',"1")
	$XmlWriter.WriteElementString('Key',"key")
	$XmlWriter.WriteElementString('Timeout',"120")
	$XmlWriter.WriteElementString('VSYS',"vsys00")
	$XmlWriter.WriteElementString('PostAddr',"https://address.of.firewall.or.api/api/")
	$XmlWriter.WriteElementString('Multipass',"0")
	$XmlWriter.WriteEndElement()
	$XmlWriter.WriteEndDocument()
	$XmlWriter.Flush()
	$XmlWriter.Close()
}

Function PostToAgent
{
	param([string]$strUserAgentData)
	If ($global:blnAgent -eq 1)
	{
		$url = "https://" + $global:strAgentServer + ":" + $global:strAgentPort + "/"
		[System.Net.HttpWebRequest]$request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($url)
		$request.Method = "PUT"
	}
	Else 
	{
		If ($global:strProxy -eq "1")
		{
		        $url = $global:strPostAddr
		}
		Else
		{
		    $url = $global:strPostAddr + "?key=" + $global:strAPIKey + "&type=user-id&action=set&vsys=" + $global:strVsys + "&client=wget&file-name=UID.xml"
		}
		[System.Net.HttpWebRequest]$request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($url)
		$request.Method = "POST"
	}
	$request.ContentType = "text/xml"
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($strUserAgentData)
	$request.ContentLength = $bytes.Length
	[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)  
        $outputStream.Close()
	try
    	{
        	[System.Net.HttpWebResponse]$response = [System.Net.HttpWebResponse]$request.GetResponse()     
        	$sr = New-Object System.IO.StreamReader($response.GetResponseStream())       
        	$txt = $sr.ReadToEnd()	
    	}
    	catch [Net.WebException] { 
        	[System.Net.HttpWebResponse] $resp = [System.Net.HttpWebResponse] $_.Exception.Response  
        
    	}
}

Function CleanMac
{
	param([string]$strMac)
	$strMac = $strMac -replace "-", ""
        $strMac = $strMac -replace "\.", ""
        $strMac = $strMac -replace ":", ""
        $strMac = $strMac.ToLower()
        return $strMac
}


Function ProcessDHCPClients
{
	If ($global:strEventUser.contains("\"))
	{
		$pos = $global:strEventUser.IndexOf("\")
		$global:strEventUser = $global:strEventUser.Substring($pos+1)
	} ElseIf ($global:strEventUser.contains("@"))
	{
		$pos = $global:strEventUser.IndexOf("@")
		$global:strEventUser = $global:strEventUser.Substring(0,$pos)
	}

	If (-Not ($global:strEventUser.contains("$")) -and -Not ($global:strEventUser.contains("host/")) )
	{
		If ($global:strCallingStation -match "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
		{
			$aMatchedIPs = @()
			$aMatchedIPs += $global:strCallingStation
		}
		Else
		{
			If ($global:blnMultipass -eq "0") {
				$aMatchedIPs = @()
				foreach ($DHCPServer in $global:aDHCPServers) 
				{
					$scopes = Get-DhcpServerv4Scope -CN $DHCPServer | select ScopeId
					foreach ($scope in $scopes) 
                                       	{
                                               $aReservations = Get-DhcpServerv4Lease -CN $DHCPServer -ScopeId $scope.ScopeID -AllLeases | select IPAddress, ClientID
                                               foreach ($reservation in $aReservations) 
                                               {
                                                    $MAC = CleanMac($reservation.ClientID)
                                                    $global:strCallingStation = CleanMac($global:strCallingStation)
                                                    If ($global:strCallingStation -eq $MAC)
                                                    {
                                                        $aMatchedIPs += $reservation.IPAddress
                                                    }
                                                }
                                        }
				}
			} 
			Else
			{
				$aMatchedIPs = @()
				$mp = 0
				While ($mp -lt 2) {
					foreach ($DHCPServer in $global:aDHCPServers) 
					{
						$scopes = Get-DhcpServerv4Scope -CN $DHCPServer | select ScopeId
						foreach ($scope in $scopes) 
                                       		{
                                               		$aReservations = Get-DhcpServerv4Lease -ScopeId $scope.ScopeID -AllLeases | select IPAddress, ClientID
                                               		foreach ($reservation in $aReservations) 
                                               		{
                                                    		$MAC = CleanMac($reservation.ClientID)
                                                    		$global:strCallingStation = CleanMac($global:strCallingStation)
                                                    		If ($global:strCallingStation -eq $MAC)
                                                    		{
                                                        		$aMatchedIPs += $reservation.IPAddress
                                                    		}
                                                	}
                                        	}
					}
					$mp = $mp + 1
				}
			}
		}
		foreach ($address in $aMatchedIPs)
		{
			If ($global:strProxy -eq "1")
			{
				[string]$strXMLLine = "<uid-message><version>1.0</version><scriptv>" + $global:strVersion + "</scriptv><type>update</type><payload><login>"
			}
			Else
			{
				[string]$strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
			}
			If ($global:blnAgent -eq "1")
			{
				$strXMLLine = $strXMLLine + "<entry name=""" + $global:strDomain + "\" + $global:strEventUser + """ ip=""" + $address + """/>"
			}
			Else
			{
				If ($global:strProxy -eq "1")
				{
					$strXMLLine = $strXMLLine + "<entry name=""" + $global:strDomain + "\" + $global:strEventUser + """ ip=""" + $address + """ timeout=""" + $global:strTimeout + """ vsys=""" + $global:strVsys + """/>"
				}
				Else 
				{
					$strXMLLine = $strXMLLine + "<entry name=""" + $global:strDomain + "\" + $global:strEventUser + """ ip=""" + $address + """ timeout=""" + $global:strTimeout + """/>"
				}
			}
			$strXMLLine = $strXMLLine + "</login></payload></uid-message>"
			PostToAgent $strXMLLine
		}
	}
}
Try
{
	If (Test-Path -Path "C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml") 
	{
		[xml]$global:cfgXML = Get-Content "C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml"
	}
	Else
	{
		CreateDefaultConfig
		[xml]$global:cfgXML = Get-Content "C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml"
	}
	LoadConfig

	If ($global:strLogFormat -eq "DTS")
	{
		#ProcessDTSLog
	}
	ElseIf ($global:strLogFormat -eq "IAS")
	{
		#ProcessIASLog
	}
	ElseIf ($global:strLogFormat -eq "DHCP")
	{
		ProcessDHCPClients
	}
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    $ErrorLog = $FailedItem + " failed with message " + $ErrorMessage
    add-content -Path "C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\uidradiuserrors.log" -Value $ErrorLog -Force
    Break
}
