[comment]: # "Auto-generated SOAR connector documentation"
# Cymon

Publisher: Splunk  
Connector Version: 1\.0\.16  
Product Vendor: eSentire  
Product Name: Cymon  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.0\.1068  

This app integrates with the Cymon to implement investigative and reputation actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cymon asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  optional  | password | api key

### Supported Actions  
[ip reputation](#action-ip-reputation) - Get information about an IP  
[lookup domain](#action-lookup-domain) - Get information about a domain  
[test connectivity](#action-test-connectivity) - Test connectivity to Cymon  
[file reputation](#action-file-reputation) - Get information about a hash  

## action: 'ip reputation'
Get information about an IP

Type: **investigate**  
Read only: **True**

This action retrieves\:<ul><li>related events</li><li>related domains</li><li>related URLs</li></ul>As a result, this action makes three separate REST calls\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.domains\.count | numeric | 
action\_result\.data\.\*\.domains\.next | string | 
action\_result\.data\.\*\.domains\.previous | string | 
action\_result\.data\.\*\.domains\.results\.\*\.created | string | 
action\_result\.data\.\*\.domains\.results\.\*\.name | string | 
action\_result\.data\.\*\.domains\.results\.\*\.updated | string | 
action\_result\.data\.\*\.events\.count | numeric | 
action\_result\.data\.\*\.events\.next | string | 
action\_result\.data\.\*\.events\.previous | string | 
action\_result\.data\.\*\.events\.results\.\*\.created | string | 
action\_result\.data\.\*\.events\.results\.\*\.description | string | 
action\_result\.data\.\*\.events\.results\.\*\.details\_url | string |  `url` 
action\_result\.data\.\*\.events\.results\.\*\.tag | string | 
action\_result\.data\.\*\.events\.results\.\*\.title | string | 
action\_result\.data\.\*\.events\.results\.\*\.updated | string | 
action\_result\.data\.\*\.urls\.count | numeric | 
action\_result\.data\.\*\.urls\.next | string | 
action\_result\.data\.\*\.urls\.previous | string | 
action\_result\.data\.\*\.urls\.results\.\*\.created | string | 
action\_result\.data\.\*\.urls\.results\.\*\.location | string |  `url`  `file name` 
action\_result\.data\.\*\.urls\.results\.\*\.updated | string | 
action\_result\.summary\.total\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Get information about a domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.created | string | 
action\_result\.data\.\*\.ips | string |  `ip` 
action\_result\.data\.\*\.name | string |  `domain` 
action\_result\.data\.\*\.sources | string | 
action\_result\.data\.\*\.updated | string | 
action\_result\.data\.\*\.urls | string |  `url` 
action\_result\.summary\.domain\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'test connectivity'
Test connectivity to Cymon

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'file reputation'
Get information about a hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash \(md5, sha1, sha256, sha512\) | string |  `hash`  `md5`  `sha1`  `sha256`  `sha512` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256`  `sha512` 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.next | string | 
action\_result\.data\.\*\.previous | string | 
action\_result\.data\.\*\.results\.\*\.created | string | 
action\_result\.data\.\*\.results\.\*\.description | string | 
action\_result\.data\.\*\.results\.\*\.details\_url | string |  `url` 
action\_result\.data\.\*\.results\.\*\.tag | string | 
action\_result\.data\.\*\.results\.\*\.title | string | 
action\_result\.data\.\*\.results\.\*\.updated | string | 
action\_result\.summary\.total\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 