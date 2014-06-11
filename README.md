## Windows Hardening Rules.

Based on **CIS Microsoft Windows Server 2012 Benchmark**

### Description
--
Subset of rules will apply as **Local Group Policy** 


###Useful info:
--

	http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/secedit_cmds.mspx?mfr=true

Idea to use:

	secedit /configure /db %temp%\temp.sdb /cfg yourcreated.inf




### Rules list
--

###### CCE-23909-5
Set 'Account lockout threshold' to '5 invalid logon attempt(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout threshold

###### CCE-24768-4
Set 'Account lockout duration' to '15 or more minute(s)' (Scored)


    Computer Configuration\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout duration

###### CCE-24840-1
Set 'Reset account lockout counter after' to '15 minute(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Reset account lockout counter after

###### CCE-25317-9
Set 'Minimum password length' to '14 or more character(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy\Minimum password length

###### CCE-24644-7
Set 'Enforce password history' to '24 or more password(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Password
Policy\Enforce password history

###### CCE-25602-4
Set 'Password must meet complexity requirements' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Password
Policy\Password must meet complexity requirements

###### CCE-23951-7
 Set 'Store passwords using reversible encryption' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Password
Policy\Store passwords using reversible encryption

###### CCE-24018-4
Set 'Minimum password age' to '1 or more day(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Password
Policy\Minimum password age

###### CCE-24535-7
et 'Maximum password age' to '60 or fewer days' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Account Policies\Password
Policy\Maximum password age

###### CCE-25088-6
Set 'Audit Policy: Account Logon: Credential Validation' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Logon\Audit Policy: Account Logon: Credential
Validation

###### CCE-24553-0
Set 'Audit Policy: Account Logon: Kerberos Authentication Service' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Logon\Audit Policy: Account Logon: Kerberos
Authentication Service

###### CCE-25549-7
Set 'Audit Policy: Account Logon: Kerberos Service Ticket Operations' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Logon\Audit Policy: Account Logon: Kerberos
Service Ticket Operations

###### CCE-24509-2
Set 'Audit Policy: Account Logon: Other Account Logon Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Logon\Audit Policy: Account Logon: Other Account
Logon Events

###### CCE-24868-2
Set 'Audit Policy: Account Management: Application Group Management' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Management\Audit Policy: Account Management:
Application Group Management

###### CCE-23482-3
Configure 'Audit Policy: Account Management: Computer Account Management' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Management\Audit Policy: Account Management:
Computer Account Management

###### CCE-25739-4
Set 'Audit Policy: Account Management: Distribution Group Management' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Management\Audit Policy: Account Management:
Distribution Group Management

###### CCE-24588-6
Set 'Audit Policy: Account Management: Other Account Management Events' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Management\Audit Policy: Account Management:
Other Account Management Events

###### CCE-23955-8
Set 'Audit Policy: Account Management: Security Group Management' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Management\Audit Policy: Account Management:
Security Group Management

###### CCE-25123-1
Set 'Audit Policy: Account Management: User Account Management' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Account Management\Audit Policy: Account Management: User
Account Management

###### CCE-25011-8
Set 'Audit Policy: Detailed Tracking: DPAPI Activity' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Detailed Tracking\Audit Policy: Detailed Tracking: DPAPI
Activity

###### CCE-25461-5
Set 'Audit Policy: Detailed Tracking: Process Creation' to 'Success' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Detailed Tracking\Audit Policy: Detailed Tracking:
Process Creation

###### CCE-25490-4
Set 'Audit Policy: Detailed Tracking: Process Termination' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Detailed Tracking\Audit Policy: Detailed Tracking:
Process Termination

###### CCE-23502-8
Set 'Audit Policy: Detailed Tracking: RPC Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Detailed Tracking\Audit Policy: Detailed Tracking: RPC
Events


###### CCE-23619-0[DOMAIN CONTROLLER]
Set 'Audit Policy: DS Access: Detailed Directory Service Replication' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\DS Access\Audit Policy: DS Access: Detailed Directory
Service Replication


###### CCE-23953-3[DOMAIN CONTROLLER]
Set 'Audit Policy: DS Access: Directory Service Access' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\DS Access\Audit Policy: DS Access: Directory Service
Access


###### CCE-24645-4[DOMAIN CONTROLLER]
Set 'Audit Policy: DS Access: Directory Service Changes' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\DS Access\Audit Policy: DS Access: Directory Service
Changes


###### CCE-24355-0[DOMAIN CONTROLLER]
Set 'Audit Policy: DS Access: Directory Service Replication' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\DS Access\Audit Policy: DS Access: Directory Service
Replication

###### CCE-24598-5
Set 'Audit Policy: Logon-Logoff: Account Lockout' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: Account Lockout

###### CCE-24404-6
Set 'Audit Policy: Logon-Logoff: IPsec Extended Mode' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: IPsec Extended
Mode

###### CCE-24584-5
Set 'Audit Policy: Logon-Logoff: IPsec Main Mode' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: IPsec Main Mode

###### CCE-23614-1
Set 'Audit Policy: Logon-Logoff: IPsec Quick Mode' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: IPsec Quick Mode

###### CCE-24901-1
Set 'Audit Policy: Logon-Logoff: Logoff' to 'Success' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: Logoff

###### CCE-23670-3
Set 'Audit Policy: Logon-Logoff: Logon' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: Logon

###### CCE-25189-2
Set 'Audit Policy: Logon-Logoff: Network Policy Server' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: Network Policy
Server

###### CCE-24494-7
Set 'Audit Policy: Logon-Logoff: Other Logon/Logoff Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: Other
Logon/Logoff Events

###### CCE-24187-7
Set 'Audit Policy: Logon-Logoff: Special Logon' to 'Success' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Logon/Logoff\Audit Policy: Logon-Logoff: Special Logon

###### CCE-25316-1
Set 'Audit Policy: Object Access: Application Generated' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Application
Generated

###### CCE-24643-9
Set 'Audit Policy: Object Access: Central Access Policy Staging' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Central Access
Policy Staging

###### CCE-23129-0
Set 'Audit Policy: Object Access: Certification Services' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Certification
Services

###### CCE-24791-6
Set 'Audit Policy: Object Access: Detailed File Share' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Detailed File
Share

###### CCE-24035-8
Set 'Audit Policy: Object Access: File Share' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: File Share

###### CCE-24456-6
Set 'Audit Policy: Object Access: File System' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: File System

###### CCE-24714-8
Set 'Audit Policy: Object Access: Filtering Platform Connection' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Filtering
Platform Connection

###### CCE-24824-5
Set 'Audit Policy: Object Access: Filtering Platform Packet Drop' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Filtering
Platform Packet Drop

###### CCE-24599-3
Set 'Audit Policy: Object Access: Handle Manipulation' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Handle
Manipulation

###### CCE-23655-4
Set 'Audit Policy: Object Access: Kernel Object' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Kernel Object

###### CCE-24236-2
Set 'Audit Policy: Object Access: Other Object Access Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Other Object
Access Events

###### CCE-23630-7
Set 'Audit Policy: Object Access: Registry' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Registry

###### CCE-22826-2
Set 'Audit Policy: Object Access: Removable Storage' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: Removable
Storage

###### CCE-24439-2
Set 'Audit Policy: Object Access: SAM' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Object Access\Audit Policy: Object Access: SAM

###### CCE-25035-7
Set 'Audit Policy: Policy Change: Audit Policy Change' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Policy Change\Audit Policy: Policy Change: Audit Policy
Change

###### CCE-25674-3
Set 'Audit Policy: Policy Change: Authentication Policy Change' to 'Success' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Policy Change\Audit Policy: Policy Change: Authentication
Policy Change

###### CCE-24421-0
Set 'Audit Policy: Policy Change: Authorization Policy Change' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Policy Change\Audit Policy: Policy Change: Authorization
Policy Change

###### CCE-24965-6
Set 'Audit Policy: Policy Change: Filtering Platform Policy Change' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Policy Change\Audit Policy: Policy Change: Filtering
Platform Policy Change

###### CCE-24259-4
Set 'Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Policy Change\Audit Policy: Policy Change: MPSSVC Rule-
Level Policy Change

###### CCE-25169-4
Set 'Audit Policy: Policy Change: Other Policy Change Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Policy Change\Audit Policy: Policy Change: Other Policy
Change Events

###### CCE-23876-6
Set 'Audit Policy: Privilege Use: Non Sensitive Privilege Use' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Privilege Use\Audit Policy: Privilege Use: Non Sensitive
Privilege Use

###### CCE-23920-2
Set 'Audit Policy: Privilege Use: Other Privilege Use Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Privilege Use\Audit Policy: Privilege Use: Other
Privilege Use Events

###### CCE-24691-8
Set 'Audit Policy: Privilege Use: Sensitive Privilege Use' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\Privilege Use\Audit Policy: Privilege Use: Sensitive
Privilege Use

###### CCE-25372-4
Set 'Audit Policy: System: IPsec Driver' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\System\Audit Policy: System: IPsec Driver

###### CCE-25187-6
Set 'Audit Policy: System: Other System Events' to 'No Auditing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\System\Audit Policy: System: Other System Events

###### CCE-25178-5
Set 'Audit Policy: System: Security State Change' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\System\Audit Policy: System: Security State Change

###### CCE-25527-3
Set 'Audit Policy: System: Security System Extension' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\System\Audit Policy: System: Security System Extension

###### CCE-25093-6
Set 'Audit Policy: System: System Integrity' to 'Success and Failure' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy
Configuration\Audit Policies\System\Audit Policy: System: System Integrity

###### CCE-23836-0
Configure 'Accounts: Rename administrator account' (Scored)

    Default Value: Administrator

###### CCE-23675-2
Configure 'Accounts: Rename guest account' (Scored)

    Default Value: Guest

###### CCE-25589-3
Set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled' (Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse

###### CCE-24075-4
Configure 'Audit: Audit the access of global system objects' (Not Scored)

    Default Value: Disabled
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects

###### CCE-24923-5
Configure 'Audit: Audit the use of Backup and Restore privilege' (Not Scored)

    Default Value: Disabled
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\fullprivilegeauditing

###### CCE-24252-9
Set 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Audit: Force audit policy subcategory settings (Windows Vista or later) to
override audit policy category settings

###### CCE-23988-9
Set 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Shut down system immediately if unable to log security audits

###### CCE-24640-5
Configure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\policies\Microsoft\windows NT\DCOM\MachineAccessRestriction

###### CCE-25572-9
Configure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\policies\Microsoft\windows NT\DCOM\MachineLaunchRestriction

###### CCE-25248-6
Configure 'Devices: Allow undock without having to log on' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\undockwithoutlogon

###### CCE-24607-4
Configure 'Devices: Restrict CD-ROM access to locally logged- on user only' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms

###### CCE-23668-7
Configure 'Devices: Restrict floppy access to locally logged-on user only' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies

###### CCE-25217-1
Set 'Devices: Allowed to format and eject removable media' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Devices: Allowed to format and eject removable media

###### CCE-25176-9
Set 'Devices: Prevent users from installing printer drivers' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Prevent users from installing printer drivers


###### CCE-25305-4[DOMAIN CONTROLLER]
Set 'Domain controller: Allow server operators to schedule tasks' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain controller: Allow server operators to schedule tasks


###### CCE-23587-9[DOMAIN CONTROLLER]
Set 'Domain controller: LDAP server signing requirements' to 'Require signing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain controller: LDAP server signing requirements


###### CCE-24692-6[DOMAIN CONTROLLER]
Set 'Domain controller: Refuse machine account password changes' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain controller: Refuse machine account password changes


###### CCE-24465-7[DOMAIN CONTROLLER]
Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Domain member: Digitally encrypt or sign secure channel data (always)


###### CCE-24414-5[DOMAIN CONTROLLER]
Set 'Domain member: Digitally encrypt secure channel data (when possible)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Domain member: Digitally encrypt secure channel data (when possible)


###### CCE-24812-0[DOMAIN CONTROLLER]
Set 'Domain member: Digitally sign secure channel data (when possible)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally sign secure channel data (when possible)


###### CCE-24243-8[DOMAIN CONTROLLER]
Set 'Domain member: Disable machine account password changes' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Domain member: Disable machine account password changes


###### CCE-23596-0[DOMAIN CONTROLLER]
Set 'Domain member: Maximum machine account password age' to '30 or fewer day(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Maximum machine account password age


###### CCE-25198-3[DOMAIN CONTROLLER]
Set 'Domain member: Require strong (Windows 2000 or later) session key' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Require strong (Windows 2000 or later) session key

###### CCE-25018-3
Configure 'Interactive logon: Display user information when the session is locked' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDispl
ayLockedUserId

###### CCE-25355-9
Configure 'Interactive logon: Message text for users attempting to log on' (Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoti
ceText

###### CCE-24020-0
Configure 'Interactive logon: Message title for users attempting to log on' (Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoti
ceCaption

###### CCE-24408-7
Configure 'Interactive logon: Require smart card' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\scforceop
tion

###### CCE-24748-6
Set 'Interactive logon: Do not display last user name' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Do not display last user name

###### CCE-25803-8
Set 'Interactive logon: Do not require CTRL+ALT+DEL' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Do not require CTRL+ALT+DEL

###### CCE-23043-3
Set 'Interactive logon: Machine inactivity limit' to '900 or fewer seconds' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Machine inactivity limit


###### CCE-24264-4[DOMAIN CONTROLLER]
Set 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' to '4 or fewer logon(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Number of previous logons to cache (in case domain
controller is not available)

###### CCE-23704-0
Set 'Interactive logon: Prompt user to change password before expiration' to '14 or more day(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Prompt user to change password before expiration


###### CCE-25643-8[DOMAIN CONTROLLER]
Set 'Interactive logon: Require Domain Controller authentication to unlock workstation' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Require Domain Controller authentication to unlock
workstation

###### CCE-24154-7
Set 'Interactive logon: Smart card removal behavior' to 'Lock Workstation' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Smart card removal behavior

###### CCE-22731-4
Set 'Interactive logon: Machine account lockout threshold' to 10 or fewer invalid logon attempts (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Interactive logon: Machine account lockout threshold


###### CCE-24969-8[SIDE EFFECT]
Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network client: Digitally sign communications (always)

###### CCE-24740-3
Set 'Microsoft network client: Digitally sign communications (if server agrees)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network client: Digitally sign communications (if server agrees)

###### CCE-24751-0
Set 'Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network client: Send unencrypted password to third-party SMB servers

###### CCE-24502-7
Configure 'Microsoft network server: Server SPN target name validation level' (Not Scored)'

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SMBServer
NameHardeningLevel

###### CCE-23897-2
Set 'Microsoft network server: Amount of idle time required before suspending session' to '15 or fewer minute(s)' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network server: Amount of idle time required before suspending
session

###### CCE-23716-4
Set 'Microsoft network server: Digitally sign communications (always)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network server: Digitally sign communications (always)

###### CCE-24354-3
Set 'Microsoft network server: Digitally sign communications (if client agrees)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network server: Digitally sign communications (if client agrees)

###### CCE-24148-9
Set 'Microsoft network server: Disconnect clients when logon hours expire' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Microsoft network server: Disconnect clients when logon hours expire

###### CCE-24205-7
Configure 'MSS: (AutoReboot) Allow Windows to automatically restart after a system crash (recommended except for highly secure environments)' (Not Scored)

    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\AutoReboot

###### CCE-24217-2
Configure 'MSS: (AutoShareServer) Enable Administrative Shares (recommended except for highly secure environments)' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShare
Server


###### CCE-24977-1[SIDE EFFECT]
Configure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect

###### CCE-24074-7
Configure 'MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Lanmanserver\Parameters\Hidden

###### CCE-24310-5
Configure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime

###### CCE-24253-7
Configure 'MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic.' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IPSEC\NoDefaultExempt

###### CCE-23715-6
Configure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnD
emand

###### CCE-23677-8
Configure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDis
covery

###### CCE-25202-3
Configure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetra
nsmissions

###### CCE-25455-7
Configure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetran
smissions

###### CCE-24927-6
Set 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)

###### CCE-24452-5
Set 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\MSS: (DisableIPSourceRouting IPv6) IP source routing protection level
(protects against packet spoofing)

###### CCE-24968-0
Set 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\MSS: (DisableIPSourceRouting) IP source routing protection level (protects
against packet spoofing)

###### CCE-23462-5
Set 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)

###### CCE-24993-8
Set 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' to '0' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver
grace period expires (0 recommended)

###### CCE-25110-8
Set 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' to '0.9 or less' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\MSS: (WarningLevel) Percentage threshold for the security event log at which
the system will generate a warning

###### CCE-23358-5
Configure 'Network access: Do not allow storage of passwords and credentials for network authentication' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds

###### CCE-25466-4
Configure 'Network access: Named Pipes that can be accessed anonymously' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessi
onPipes

###### CCE-25592-7
Configure 'Network access: Shares that can be accessed anonymously' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessi
onShares

###### CCE-24597-7
Set 'Network access: Allow anonymous SID/Name translation' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Network access: Allow anonymous SID/Name translation

###### CCE-24774-2
Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Network access: Do not allow anonymous enumeration of SAM accounts and shares

###### CCE-23082-1
Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Network access: Do not allow anonymous enumeration of SAM accounts

###### CCE-23807-1
Set 'Network access: Let Everyone permissions apply to anonymous users' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Network access: Let Everyone permissions apply to anonymous users


###### CCE-25426-8131. Set 'Network access: Remotely accessible registry paths and sub-paths' to 'System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog icrosoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Softwar (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths and sub-paths

Set to:
	System\CurrentControlSet\Control\Print\Printers
	System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server
	Software\Microsoft\Windows NT\CurrentVersion\Print
	Software\Microsoft\Windows NT\CurrentVersion\Windows
	System\CurrentControlSet\Control\ContentIndex
	System\CurrentControlSet\Control\Terminal Server
	System\CurrentControlSet\Control\Terminal Server\UserConfig
	System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
	Software\Microsoft\Windows NT\CurrentVersion\Prefab
	System\CurrentControlSet\Services\SysmonLog


###### CCE-23899-8132. Set 'Network access: Remotely accessible registry paths' to 'System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications icrosoft\Windows NT\CurrentVersion' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths

Set to:
	System\CurrentControlSet\Control\ProductOptions
	System\CurrentControlSet\Control\Server Applications
	Software\Microsoft\Windows NT\CurrentVersion

###### CCE-24564-7
Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Network access: Restrict anonymous access to Named Pipes and Shares

###### CCE-22742-1
Set 'Network access: Sharing and security model for local accounts' to 'Classic - local users authenticate as themselves' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Network access: Sharing and security model for local accounts

###### CCE-25299-9
Configure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID

###### CCE-24147-1
Configure 'Network Security: Configure encryption types allowed for Kerberos' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\
Parameters\SupportedEncryptionTypes

###### CCE-25367-4
Configure 'Network security: Force logoff when logon hours expire' (Not Scored)

    WHAT??!

###### CCE-25046-4
Configure 'Network Security: Restrict NTLM: Add remote server exceptions for NTLM authentication' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers

###### CCE-23483-1
Configure 'Network Security: Restrict NTLM: Add server exceptions in this domain' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DCAllowedNTLM Servers

###### CCE-23338-7
Configure 'Network Security: Restrict NTLM: Audit Incoming NTLM Traffic' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic

###### CCE-24238-8
Configure 'Network Security: Restrict NTLM: Audit NTLM authentication in this domain' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain

###### CCE-24393-1
Configure 'Network Security: Restrict NTLM: Incoming NTLM traffic' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic

###### CCE-25645-3
Configure 'Network Security: Restrict NTLM: NTLM authentication in this domain' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain

###### CCE-25095-1
Configure 'Network Security: Restrict NTLM: Outgoing NTLM traffic to remote servers' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic


###### CCE-25508-3[DOMAIN CONTROLLER]
Set 'Network security: Allow Local System to use computer identity for NTLM' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network security: Allow Local System to use computer identity for NTLM


###### CCE-25531-5[DOMAIN CONTROLLER]
Set 'Network security: Allow LocalSystem NULL session fallback' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network security: Allow LocalSystem NULL session fallback

###### CCE-24150-5
Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network security: Do not store LAN Manager hash value on next password change

###### CCE-24650-4
Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network security: LAN Manager authentication level

###### CCE-25245-2
Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network security: LDAP client signing requirements


###### CCE-24783-3[SIDE EFFECT]
Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security,Require 128-bit encryption' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network security: Minimum session security for NTLM SSP based (including secure RPC) client

###### CCE-25264-3
Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' to 'Require NTLMv2 session security,Require 128-bit encryption' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) servers

###### CCE-24470-7
Set 'Recovery console: Allow automatic administrative logon' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\Recovery console: Allow automatic administrative logon

###### CCE-25274-2
Set 'Recovery console: Allow floppy copy and access to all drives and all folders' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Recovery console: Allow floppy copy and access to all drives and all folders

###### CCE-25100-9
Set 'Shutdown: Allow system to be shut down without having to log on' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Shutdown: Allow system to be shut down without having to log on

###### CCE-25120-7
Set 'Shutdown: Clear virtual memory pagefile' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\Shutdown: Clear virtual memory pagefile

###### CCE-23711-5
Configure 'System cryptography: Force strong key protection for user keys stored on the computer' (Not Scored)

    HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection

###### CCE-23921-0
Set 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\System cryptography: Use FIPS compliant algorithms for encryption, hashing,
and signing

###### CCE-24870-8
Set 'System objects: Require case insensitivity for non- Windows subsystems' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\SecurityOptions\System objects: Require case insensitivity for non-Windows subsystems

###### CCE-24633-0
Set 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\System objects: Strengthen default permissions of internal system objects
(e.g. Symbolic Links)

###### CCE-24878-1
Configure 'System settings: Optional subsystems' (Not Scored)

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional

###### CCE-24939-1
Set 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security
Options\System settings: Use Certificate Rules on Windows Executables for Software
Restriction Policies

###### CCE-24134-9
Set 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account

###### CCE-23295-9
Set 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop

###### CCE-23877-4
Set 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for consent for non-Windows binaries' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behaviour of the elevation prompt for administrators in Admin Approval Mode

###### CCE-24519-1
Set 'User Account Control: Behavior of the elevation prompt for standard users' to 'Prompt for credentials' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for standard users

###### CCE-24498-8
Set 'User Account Control: Detect application installations and prompt for elevation' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Detect application installations and prompt for
elevation

###### CCE-23880-8
Set 'User Account Control: Only elevate executables that are signed and validated' to 'Disabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Only elevate executables that are signed and validated

###### CCE-25471-4
Set 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Only elevate UIAccess applications that are installed in
secure locations

###### CCE-23653-9
Set 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode

###### CCE-23656-2
Set 'User Account Control: Switch to the secure desktop when prompting for elevation' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Switch to the secure desktop when prompting for elevation

###### CCE-24231-3
Set 'User Account Control: Virtualize file and registry write failures to per-user locations' to 'Enabled' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations

###### CCE-23273-6
Configure 'Deny log on through Remote Desktop Services' (Not Scored)

    Optional

###### CCE-25619-8
Configure 'Log on as a service' (Not Scored)

    Optional

###### CCE-25683-4
Set 'Access Credential Manager as a trusted caller' to 'No One' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller

###### CCE-24938-3
Configure 'Access this computer from the network' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network

The recommended state for this setting is:
	- Administrators, Authenticated Users

###### CCE-25043-1
Set 'Act as part of the operating system' to 'No One' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system


###### CCE-23271-0[DOMAIN CONTROLLER]
Set 'Add workstations to domain' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Add workstations to domain

###### CCE-25112-4
Set 'Adjust memory quotas for a process' to 'Administrators, Local Service, Network Service' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Adjust memory quotas for a process

###### CCE-25228-8
Set 'Allow log on locally' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally

###### CCE-24406-1
Set 'Allow log on through Remote Desktop Services' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services

###### CCE-25380-7
Set 'Back up files and directories' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Back up files and directories

###### CCE-25271-8
Configure 'Bypass traverse checking' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights
Assignment\Bypass traverse checking

The recommended state for this setting is:
	- Administrators, Authenticated Users, Backup Operators, Local Service, Network Service.

###### CCE-24185-1
Set 'Change the system time' to 'LOCAL SERVICE, Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the system time

Set the following Group Policy setting to:
	- LOCAL SERVICE, Administrators.

###### CCE-24632-2
Set 'Change the time zone' to 'LOCAL SERVICE, Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the time zone

Set the following Group Policy setting to:
	- LOCAL SERVICE, Administrators.

###### CCE-23972-3
Set 'Create a pagefile' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile

###### CCE-23939-2
Set 'Create a token object' to 'No One' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a token object

###### CCE-23850-1
Set 'Create global objects' to 'Administrators, SERVICE, LOCAL SERVICE, NETWORK SERVICE' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create global objects

###### CCE-23723-0
Set 'Create permanent shared objects' to 'No One' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create permanent shared objects

###### CCE-24549-8
Set 'Create symbolic links' to 'Administrators' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create symbolic links


###### CCE-23648-9[SIDE EFFECT]
Set 'Debug programs' to 'Administrators' (Scored)

    Windows Product Updates may stop responding or may use most or all the CPU resources, in the Microsoft Knowledge Base (http://go.microsoft.com/fwlink/?LinkId=100747).

Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Debug programs

###### CCE-24188-5
Set 'Deny access to this computer from the network' to 'Guests' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network

###### CCE-25215-5
Set 'Deny log on as a batch job' to 'Guests' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job

###### CCE-23117-5
Set 'Deny log on as a service' to 'No One' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service

###### CCE-24460-8
Set 'Deny log on locally' to 'Guests' (Scored)

    Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on locally

