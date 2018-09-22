$fwName = "fw01"
$rgName = 'pentest-rg'
$last_updated = Get-Date -Format yyyyMMddThhmmssZ
$rule_file_path = "D:\Dev\azFirewall\bl"
$cleaned_file_name = "$rule_file_path" + "$last_updated" + ".txt"

$azFirewall = Get-AzureRmFirewall -Name $fwName -ResourceGroupName $rgName
if (!$azFirewall) {
    throw "No target Azure Firewall resource is not found"
}
else {
    Write-Output $azFirewall.Name
}

# Download and process host list
Invoke-WebRequest http://www.malwaredomainlist.com/hostslist/hosts.txt -OutFile $cleaned_file_name
$rawList = Get-Content -path $cleaned_file_name | Select-Object -Skip 6 
$cleanedList = $rawList


# Create multiple rules
$ruleset = @()
Foreach ($hostList in $cleanedList) { 
    $trimmedHost = ($hostList.Trim("127.0.0.1")).Trim()
    ForEach ($blockUrl in $trimmedHost) {
        $ruleset += New-AzureRmFirewallApplicationRule -Name $blockUrl `
            -SourceAddress * `
            -Protocol Http:80, Https:443 `
            -TargetFqdn $blockUrl -Verbose
    }
}

# Create a new application rule collection
$ruleCollection = New-AzureRmFirewallApplicationRuleCollection -Name MDLHost `
    -Priority 300 `
    -Rule $ruleset  `
    -ActionType "Deny"

$azFirewall.ApplicationRuleCollections = $ruleCollection
Set-AzureRmFirewall -AzureFirewall $azFirewall
