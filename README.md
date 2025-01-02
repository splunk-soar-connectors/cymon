[comment]: # "Auto-generated SOAR connector documentation"
# Cymon

Publisher: Splunk  
Connector Version: 1.0.18  
Product Vendor: eSentire  
Product Name: Cymon  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 4.0.1068  

This app integrates with the Cymon to implement investigative and reputation actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cymon asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** |  optional  | password | api key

### Supported Actions  
[ip reputation](#action-ip-reputation) - Get information about an IP  
[lookup domain](#action-lookup-domain) - Get information about a domain  
[test connectivity](#action-test-connectivity) - Test connectivity to Cymon  
[file reputation](#action-file-reputation) - Get information about a hash  

## action: 'ip reputation'
Get information about an IP

Type: **investigate**  
Read only: **True**

This action retrieves:<ul><li>related events</li><li>related domains</li><li>related URLs</li></ul>As a result, this action makes three separate REST calls.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   1.1.1.1 
action_result.data.\*.domains.count | numeric |  |   357 
action_result.data.\*.domains.next | string |  |  
action_result.data.\*.domains.previous | string |  |  
action_result.data.\*.domains.results.\*.created | string |  |   2018-08-24T12:35:14Z 
action_result.data.\*.domains.results.\*.name | string |  |   kk347.ncxkg.cc 
action_result.data.\*.domains.results.\*.updated | string |  |   2018-08-26T04:56:59Z 
action_result.data.\*.events.count | numeric |  |   469 
action_result.data.\*.events.next | string |  |  
action_result.data.\*.events.previous | string |  |  
action_result.data.\*.events.results.\*.created | string |  |   2018-11-22T19:04:18Z 
action_result.data.\*.events.results.\*.description | string |  |   Domain: www.nlus-romania.ro 
action_result.data.\*.events.results.\*.details_url | string |  `url`  |   http://urlquery.net/report/09aaf220-5281-4bbb-b49a-7b5ccb3d17cf 
action_result.data.\*.events.results.\*.tag | string |  |   phishing 
action_result.data.\*.events.results.\*.title | string |  |   Phishing reported by Google SafeBrowsing 
action_result.data.\*.events.results.\*.updated | string |  |   2018-11-22T19:04:18Z 
action_result.data.\*.urls.count | numeric |  |   189 
action_result.data.\*.urls.next | string |  |  
action_result.data.\*.urls.previous | string |  |  
action_result.data.\*.urls.results.\*.created | string |  |   2017-12-09T04:58:27Z 
action_result.data.\*.urls.results.\*.location | string |  `url`  `file name`  |   http://save102-001-site1.mywindowshosting.com/w2.html 
action_result.data.\*.urls.results.\*.updated | string |  |   2017-12-09T04:58:49Z 
action_result.summary.total_count | numeric |  |   1015 
action_result.message | string |  |   IP Reputation succeeded 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup domain'
Get information about a domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.parameter.domain | string |  `domain`  |   www.splunk.com 
action_result.data.\*.created | string |  |   2015-05-06T11:10:32Z 
action_result.data.\*.ips | string |  `ip`  |   54.230.131.46 
action_result.data.\*.name | string |  `domain`  |   www.splunk.com 
action_result.data.\*.sources | string |  |   urlquery.net 
action_result.data.\*.updated | string |  |   2017-02-10T21:55:31Z 
action_result.data.\*.urls | string |  `url`  |   https://cymon.io/api/nexus/v1/url/http%253A%252F%252Fwww.splunk.com%252Fen_us%252Fsolutions%252Fsolution-areas%252Fsecurity-and-fraud%252Fsplunk-app-for-enterprise+%2528...%2529 
action_result.summary.domain_count | numeric |  |   2 
action_result.message | string |  |   Lookup Domain succeeded 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

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
**hash** |  required  | Hash (md5, sha1, sha256, sha512) | string |  `hash`  `md5`  `sha1`  `sha256`  `sha512` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.parameter.hash | string |  `hash`  `md5`  `sha1`  `sha256`  `sha512`  |   8743b52063cd84097a65d1633f5c74f5 
action_result.data.\*.count | numeric |  |   0 
action_result.data.\*.next | string |  |  
action_result.data.\*.previous | string |  |  
action_result.data.\*.results.\*.created | string |  |  
action_result.data.\*.results.\*.description | string |  |   Test Description of File 
action_result.data.\*.results.\*.details_url | string |  `url`  |   http://urlquery.net/report/09aaf220-5200-4bbb-b49a-7b5ccb3d17cf 
action_result.data.\*.results.\*.tag | string |  |  
action_result.data.\*.results.\*.title | string |  |   Test Title 
action_result.data.\*.results.\*.updated | string |  |  
action_result.summary.total_count | numeric |  |   0 
action_result.message | string |  |   File reputation succeeded 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 