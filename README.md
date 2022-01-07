[comment]: # "Auto-generated SOAR connector documentation"
# Tufin SecureTrack

Publisher: Splunk  
Connector Version: 2\.0\.2  
Product Vendor: Tufin  
Product Name: Tufin SecureTrack  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports investigative actions on Tufin SecureTrack

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Tufin SecureTrack asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Server URL \(e\.g\. https\://10\.10\.10\.10\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[lookup ip](#action-lookup-ip) - Lookup IP/CIDR info  
[trace route](#action-trace-route) - Check connectivity between source and destination network  

## action: 'test connectivity'
Validate credentials provided for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Lookup IP/CIDR info

Type: **investigate**  
Read only: **True**

This action can also be used to check if the specified IP is blocked by testing the value of the <b>action\_result\.summary\.is\_blocked</b> response data path\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP/CIDR to lookup | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.\@xsi\.type | string | 
action\_result\.data\.\*\.acceleration\_breaker | boolean | 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.additional\_parameter\.\*\.display\_name | string | 
action\_result\.data\.\*\.additional\_parameter\.\*\.id | numeric | 
action\_result\.data\.\*\.additional\_parameter\.\*\.name | string | 
action\_result\.data\.\*\.application\.\*\.display\_name | string | 
action\_result\.data\.\*\.application\.\*\.id | numeric | 
action\_result\.data\.\*\.application\.\*\.name | string | 
action\_result\.data\.\*\.authentication\_rule | boolean | 
action\_result\.data\.\*\.binding\.acl\.global | boolean | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.acl\_name | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.device\_id | numeric | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.direction | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.global | boolean | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.id | numeric | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.ip | string |  `ip` 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.netmask | string |  `ip` 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.precedence | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.vendorAttachmentPolicy | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.visibility | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.name | string | 
action\_result\.data\.\*\.binding\.acl\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.access\_allowed | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.any\_zone | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.application\_id | numeric | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.class\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.comment | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.deviceName | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.device\_id | numeric | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.display\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.domain\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.display | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.id | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.link\.\@href | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.member | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.type | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.global | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.id | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.implicit | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.management\_domain | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.display | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.id | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.link\.\@href | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.member | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.type | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.nat\_info\.id | numeric | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.nat\_info\.interface\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.type\_on\_device | string | 
action\_result\.data\.\*\.binding\.default | boolean | 
action\_result\.data\.\*\.binding\.device\_policy\_id | numeric | 
action\_result\.data\.\*\.binding\.direction | string | 
action\_result\.data\.\*\.binding\.display\_name | string | 
action\_result\.data\.\*\.binding\.from\_collection | string | 
action\_result\.data\.\*\.binding\.from\_type | string | 
action\_result\.data\.\*\.binding\.from\_zone\.\*\.global | boolean | 
action\_result\.data\.\*\.binding\.from\_zone\.\*\.id | numeric | 
action\_result\.data\.\*\.binding\.from\_zone\.\*\.name | string | 
action\_result\.data\.\*\.binding\.from\_zone\.global | boolean | 
action\_result\.data\.\*\.binding\.from\_zone\.id | numeric | 
action\_result\.data\.\*\.binding\.from\_zone\.name | string | 
action\_result\.data\.\*\.binding\.ip\_type\.ipv4 | boolean | 
action\_result\.data\.\*\.binding\.ip\_type\.ipv6 | boolean | 
action\_result\.data\.\*\.binding\.nat\_stage | string | 
action\_result\.data\.\*\.binding\.nat\_type | string | 
action\_result\.data\.\*\.binding\.policy\.admin\_domain | string |  `domain` 
action\_result\.data\.\*\.binding\.policy\.admin\_domain\_id | numeric | 
action\_result\.data\.\*\.binding\.policy\.id | numeric | 
action\_result\.data\.\*\.binding\.policy\.itg | string | 
action\_result\.data\.\*\.binding\.policy\.itg\_id | numeric | 
action\_result\.data\.\*\.binding\.policy\.name | string | 
action\_result\.data\.\*\.binding\.policy\.unique\_active\_in\_itg | boolean | 
action\_result\.data\.\*\.binding\.policy\_map\_name | string | 
action\_result\.data\.\*\.binding\.postnat\_iface | string | 
action\_result\.data\.\*\.binding\.prenat\_iface | string | 
action\_result\.data\.\*\.binding\.rule\_count | numeric | 
action\_result\.data\.\*\.binding\.security\_rule\_count | numeric | 
action\_result\.data\.\*\.binding\.to\_collection | string | 
action\_result\.data\.\*\.binding\.to\_type | string | 
action\_result\.data\.\*\.binding\.to\_zone\.\*\.global | boolean | 
action\_result\.data\.\*\.binding\.to\_zone\.\*\.id | numeric | 
action\_result\.data\.\*\.binding\.to\_zone\.\*\.name | string | 
action\_result\.data\.\*\.binding\.to\_zone\.global | boolean | 
action\_result\.data\.\*\.binding\.to\_zone\.id | numeric | 
action\_result\.data\.\*\.binding\.to\_zone\.name | string | 
action\_result\.data\.\*\.binding\.uid | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.cp\_uid | string | 
action\_result\.data\.\*\.dest\_networks\_negated | boolean | 
action\_result\.data\.\*\.dest\_services\_negated | boolean | 
action\_result\.data\.\*\.device\_id | numeric | 
action\_result\.data\.\*\.disabled | boolean | 
action\_result\.data\.\*\.dst\_network\.\*\.display\_name | string | 
action\_result\.data\.\*\.dst\_network\.\*\.id | numeric | 
action\_result\.data\.\*\.dst\_network\.\*\.name | string | 
action\_result\.data\.\*\.dst\_service\.\*\.DM\_INLINE\_members\.member\.\*\.display\_name | string |  `url` 
action\_result\.data\.\*\.dst\_service\.\*\.DM\_INLINE\_members\.member\.\*\.id | numeric | 
action\_result\.data\.\*\.dst\_service\.\*\.DM\_INLINE\_members\.member\.\*\.name | string | 
action\_result\.data\.\*\.dst\_service\.\*\.display\_name | string | 
action\_result\.data\.\*\.dst\_service\.\*\.id | numeric | 
action\_result\.data\.\*\.dst\_service\.\*\.name | string | 
action\_result\.data\.\*\.external | boolean | 
action\_result\.data\.\*\.fmg\_from\_zone | string | 
action\_result\.data\.\*\.fmg\_to\_zone | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.implicit | boolean | 
action\_result\.data\.\*\.install\.\*\.display\_name | string | 
action\_result\.data\.\*\.install\.\*\.id | numeric | 
action\_result\.data\.\*\.install\.\*\.name | string | 
action\_result\.data\.\*\.ip\_type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.option | string | 
action\_result\.data\.\*\.order | numeric | 
action\_result\.data\.\*\.priority | numeric | 
action\_result\.data\.\*\.rule\_number | numeric | 
action\_result\.data\.\*\.rule\_type | string | 
action\_result\.data\.\*\.src\_network\.\*\.DM\_INLINE\_members\.member\.\*\.display\_name | string | 
action\_result\.data\.\*\.src\_network\.\*\.DM\_INLINE\_members\.member\.\*\.id | numeric | 
action\_result\.data\.\*\.src\_network\.\*\.DM\_INLINE\_members\.member\.\*\.name | string | 
action\_result\.data\.\*\.src\_network\.\*\.display\_name | string | 
action\_result\.data\.\*\.src\_network\.\*\.id | numeric | 
action\_result\.data\.\*\.src\_network\.\*\.name | string | 
action\_result\.data\.\*\.src\_networks\_negated | boolean | 
action\_result\.data\.\*\.src\_services\_negated | boolean | 
action\_result\.data\.\*\.textual\_rep | string | 
action\_result\.data\.\*\.time\.display\_name | string | 
action\_result\.data\.\*\.time\.id | numeric | 
action\_result\.data\.\*\.time\.name | string | 
action\_result\.data\.\*\.track\.interval | string | 
action\_result\.data\.\*\.track\.level | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.uid | string | 
action\_result\.data\.\*\.users\.\*\.display\_name | string | 
action\_result\.data\.\*\.users\.\*\.id | numeric | 
action\_result\.data\.\*\.users\.\*\.name | string | 
action\_result\.data\.\*\.vpn\.display\_name | string | 
action\_result\.data\.\*\.vpn\.id | numeric | 
action\_result\.data\.\*\.vpn\.name | string | 
action\_result\.summary\.is\_blocked | boolean | 
action\_result\.summary\.total\_rules | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'trace route'
Check connectivity between source and destination network

Type: **investigate**  
Read only: **True**

One of the <b>source\_ip</b> or <b>destination\_ip</b> parameters need to be specified\. If <b>source\_ip</b> or <b>destination\_ip</b> parameter is not specified, the action will use 'Any'\. This action returns a list of all enabled rules, which matches the specified source and destination network\. The rules are sorted according to rule order\. <br/>Supported <b>protocol</b>\: <ul><li>Any</li><li>TCP</li><li>UDP</li><li>ICMP</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**source\_ip** |  optional  | Source IP/CIDR | string |  `ip` 
**destination\_ip** |  optional  | Destination IP/CIDR | string |  `ip` 
**protocol** |  optional  | Protocol \(Default\: Any\) | string | 
**port** |  optional  | Port | numeric |  `port` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.destination\_ip | string |  `ip` 
action\_result\.parameter\.port | string |  `port` 
action\_result\.parameter\.protocol | string | 
action\_result\.parameter\.source\_ip | string |  `ip` 
action\_result\.data\.\*\.\@xsi\.type | string | 
action\_result\.data\.\*\.acceleration\_breaker | boolean | 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.additional\_parameter\.\*\.display\_name | string | 
action\_result\.data\.\*\.additional\_parameter\.\*\.id | numeric | 
action\_result\.data\.\*\.additional\_parameter\.\*\.name | string | 
action\_result\.data\.\*\.additional\_parameter\.display\_name | string | 
action\_result\.data\.\*\.additional\_parameter\.id | numeric | 
action\_result\.data\.\*\.additional\_parameter\.name | string | 
action\_result\.data\.\*\.application\.\*\.display\_name | string | 
action\_result\.data\.\*\.application\.\*\.id | numeric | 
action\_result\.data\.\*\.application\.\*\.name | string | 
action\_result\.data\.\*\.authentication\_rule | boolean | 
action\_result\.data\.\*\.binding\.acl\.global | boolean | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.acl\_name | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.device\_id | numeric | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.direction | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.global | boolean | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.id | numeric | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.interface\_ips\.interface\_ip\.ip | string |  `ip` 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.interface\_ips\.interface\_ip\.netmask | string |  `ip` 
action\_result\.data\.\*\.binding\.acl\.interfaces\.\*\.name | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.acl\_name | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.device\_id | numeric | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.direction | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.global | boolean | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.id | numeric | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.ip | string |  `ip` 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.netmask | string |  `ip` 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.precedence | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.vendorAttachmentPolicy | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.interface\_ips\.interface\_ip\.visibility | string | 
action\_result\.data\.\*\.binding\.acl\.interfaces\.name | string | 
action\_result\.data\.\*\.binding\.acl\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.access\_allowed | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.any\_zone | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.application\_id | numeric | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.class\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.comment | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.deviceName | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.device\_id | numeric | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.display\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.domain\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.display | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.id | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.link\.\@href | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.member | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.exclusion\.\*\.type | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.global | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.id | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.implicit | boolean | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.management\_domain | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.display | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.id | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.link\.\@href | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.member | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.member\.\*\.type | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.nat\_info\.id | numeric | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.nat\_info\.interface\_name | string | 
action\_result\.data\.\*\.binding\.cloudSecurityGroupDTO\.type\_on\_device | string | 
action\_result\.data\.\*\.binding\.default | boolean | 
action\_result\.data\.\*\.binding\.device\_policy\_id | numeric | 
action\_result\.data\.\*\.binding\.direction | string | 
action\_result\.data\.\*\.binding\.display\_name | string | 
action\_result\.data\.\*\.binding\.from\_collection | string | 
action\_result\.data\.\*\.binding\.from\_type | string | 
action\_result\.data\.\*\.binding\.from\_zone\.\*\.global | boolean | 
action\_result\.data\.\*\.binding\.from\_zone\.\*\.id | numeric | 
action\_result\.data\.\*\.binding\.from\_zone\.\*\.name | string | 
action\_result\.data\.\*\.binding\.from\_zone\.global | boolean | 
action\_result\.data\.\*\.binding\.from\_zone\.id | numeric | 
action\_result\.data\.\*\.binding\.from\_zone\.name | string | 
action\_result\.data\.\*\.binding\.ip\_type | string | 
action\_result\.data\.\*\.binding\.ip\_type\.ipv4 | boolean | 
action\_result\.data\.\*\.binding\.ip\_type\.ipv6 | boolean | 
action\_result\.data\.\*\.binding\.nat\_stage | string | 
action\_result\.data\.\*\.binding\.nat\_type | string | 
action\_result\.data\.\*\.binding\.policy\.admin\_domain | string |  `domain` 
action\_result\.data\.\*\.binding\.policy\.admin\_domain\_id | numeric | 
action\_result\.data\.\*\.binding\.policy\.id | numeric | 
action\_result\.data\.\*\.binding\.policy\.itg | string | 
action\_result\.data\.\*\.binding\.policy\.itg\_id | numeric | 
action\_result\.data\.\*\.binding\.policy\.name | string | 
action\_result\.data\.\*\.binding\.policy\.unique\_active\_in\_itg | boolean | 
action\_result\.data\.\*\.binding\.policy\_map\_name | string | 
action\_result\.data\.\*\.binding\.postnat\_iface | string | 
action\_result\.data\.\*\.binding\.prenat\_iface | string | 
action\_result\.data\.\*\.binding\.rule\_count | numeric | 
action\_result\.data\.\*\.binding\.security\_rule\_count | numeric | 
action\_result\.data\.\*\.binding\.to\_collection | string | 
action\_result\.data\.\*\.binding\.to\_type | string | 
action\_result\.data\.\*\.binding\.to\_zone\.\*\.global | boolean | 
action\_result\.data\.\*\.binding\.to\_zone\.\*\.id | numeric | 
action\_result\.data\.\*\.binding\.to\_zone\.\*\.name | string | 
action\_result\.data\.\*\.binding\.to\_zone\.global | boolean | 
action\_result\.data\.\*\.binding\.to\_zone\.id | numeric | 
action\_result\.data\.\*\.binding\.to\_zone\.name | string | 
action\_result\.data\.\*\.binding\.uid | string | 
action\_result\.data\.\*\.comment | numeric | 
action\_result\.data\.\*\.cp\_uid | string | 
action\_result\.data\.\*\.dest\_networks\_negated | boolean | 
action\_result\.data\.\*\.dest\_services\_negated | boolean | 
action\_result\.data\.\*\.device\_id | numeric | 
action\_result\.data\.\*\.device\_name | string | 
action\_result\.data\.\*\.disabled | boolean | 
action\_result\.data\.\*\.dst\_network\.\*\.display\_name | string | 
action\_result\.data\.\*\.dst\_network\.\*\.id | numeric | 
action\_result\.data\.\*\.dst\_network\.\*\.name | string | 
action\_result\.data\.\*\.dst\_service\.\*\.display\_name | string | 
action\_result\.data\.\*\.dst\_service\.\*\.id | numeric | 
action\_result\.data\.\*\.dst\_service\.\*\.name | string | 
action\_result\.data\.\*\.external | boolean | 
action\_result\.data\.\*\.fmg\_from\_zone | string | 
action\_result\.data\.\*\.fmg\_to\_zone | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.implicit | boolean | 
action\_result\.data\.\*\.install\.\*\.display\_name | string | 
action\_result\.data\.\*\.install\.\*\.id | numeric | 
action\_result\.data\.\*\.install\.\*\.name | string | 
action\_result\.data\.\*\.ip\_type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.option | string | 
action\_result\.data\.\*\.order | numeric | 
action\_result\.data\.\*\.priority | numeric | 
action\_result\.data\.\*\.rule\_number | numeric | 
action\_result\.data\.\*\.rule\_type | string | 
action\_result\.data\.\*\.src\_network\.\*\.display\_name | string | 
action\_result\.data\.\*\.src\_network\.\*\.id | numeric | 
action\_result\.data\.\*\.src\_network\.\*\.name | string | 
action\_result\.data\.\*\.src\_networks\_negated | boolean | 
action\_result\.data\.\*\.src\_services\_negated | boolean | 
action\_result\.data\.\*\.textual\_rep | string | 
action\_result\.data\.\*\.time\.display\_name | string | 
action\_result\.data\.\*\.time\.id | numeric | 
action\_result\.data\.\*\.time\.name | string | 
action\_result\.data\.\*\.track\.interval | string | 
action\_result\.data\.\*\.track\.level | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.uid | string | 
action\_result\.data\.\*\.users\.\*\.display\_name | string | 
action\_result\.data\.\*\.users\.\*\.id | numeric | 
action\_result\.data\.\*\.users\.\*\.name | string | 
action\_result\.data\.\*\.vpn\.display\_name | string | 
action\_result\.data\.\*\.vpn\.id | numeric | 
action\_result\.data\.\*\.vpn\.name | string | 
action\_result\.summary\.allowed\_traffic | boolean | 
action\_result\.summary\.total\_rules | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 