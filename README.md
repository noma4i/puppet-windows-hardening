Useful info:
	
	http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/secedit_cmds.mspx?mfr=true

Idea to use:

	secedit /configure /db %temp%\temp.sdb /cfg yourcreated.inf

###### CCE-23909-5
Set 'Account lockout threshold' to '5 invalid logon attempt(s)' (Scored)

>Computer Configuration\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout threshold

###### CCE-24768-4
Set 'Account lockout duration' to '15 or more minute(s)' (Scored)


>Computer Configuration\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout duration
    


