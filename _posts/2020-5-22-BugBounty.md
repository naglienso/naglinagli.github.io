---
layout: single
title: My Modern interpretation of The Web Application Hackers Handbook
date: 2020-5-27
classes: wide
header:
  teaser: /images/TOOLONG.jpg
tags:

  -BugBounty
--- 
**Based on The Web Application Hackers Handbook2 and modern toolset**

![MeMe](/images/TOOLONG.jpg)

## Introduction

This blog post is intended to summary my reading of "The Web Application Hackers Handbook2".

I will assemble a modern methodology with present trending tools based on Chapter 21.


![Methodology_Chapter21](/images/Methodology.png)

## Tools summary:
1. ffuf - content discovery fuzzing tool written in go - <https://github.com/ffuf/ffuf>
2. dirsearch - Python content discovery fuzzing tool - <https://github.com/maurosoria/dirsearch>
3. OWASP Amass - Asset Discovery tool - <https://github.com/OWASP/Amass>
4. Sublist3r - Asset Discovery enumerating subdomains using OSINT - <https://github.com/aboul3la/Sublist3r>
5. subfinder - Subdomain discovery tool - <https://github.com/projectdiscovery/subfinder>
6. BurpSuite - Web Proxy tool - <https://portswigger.net/burp>
7. Wappalyzer - Web extension to identify technology on websites - <https://www.wappalyzer.com/>
8. aquatone - tool for visual inspection of websites across a large amount of hosts - <https://github.com/michenriksen/aquatone>
9. httprobe - Take a list of domains and probe for working http and https servers - <https://github.com/tomnomnom/httprobe>
10. assetfinder - Finding domains and subdomains tool written in go - <https://github.com/tomnomnom/assetfinder>
11. waybackurls - fetch known URLs from the Wayback Machine for *.domain - <https://github.com/tomnomnom/waybackurls>
12. SecLists - multiple types of lists used during security assessments - <https://github.com/danielmiessler/SecLists>
13. fprobe - probe for working http/https server - <https://github.com/theblackturtle/fprobe>
14. sqlmap - Automatic SQL injection and database takeover tool - <https://github.com/sqlmapproject/sqlmap>
15. subjack - Subdomain Takeover tool written in Go - <https://github.com/haccer/subjack>
16. gau - Fetch known URLs from multiple resources - <https://github.com/lc/gau>
17. ZDNS - Fast CLI DNS Lookup Tool - <https://github.com/zmap/zdns>
18. hakrawler - Simple, fast web crawler - <https://github.com/hakluke/hakrawler>
19. anti-burl - probe Urls for 200 OK response code - <https://github.com/tomnomnom/hacks/tree/master/anti-burl>
20. jq - jq is a lightweight and flexible command-line JSON processor - <https://github.com/stedolan/jq>
21. gf - A wrapper around grep, to help you grep for things - <https://github.com/tomnomnom/gf>
22. Paramspider - Mining parameters from dark corners of Web Archives - <https://github.com/devanshbatham/ParamSpider>
23. getJS - A tool to fastly get all javascript sources/files - <https://github.com/003random/getJS>
24. LiveTargetsFinder - automating the usage of Massdns, Masscan and nmap - <https://github.com/allyomalley/LiveTargetsFinder>
25. OpenRedireX - Open redirect Fuzzer - <https://github.com/devanshbatham/OpenRedireX>
26. SSRFire - An automated SSRF finder using gau, ffuf, qsreplace and OpenRedirex - <https://github.com/micha3lb3n/SSRFire>
27. XSRFProbe - Cross Site Request Forgery (CSRF) Audit and Exploitation Toolkit - <https://github.com/0xInfection/XSRFProbe>
28. XSStrike - advanced XSS scanner - <https://github.com/s0md3v/XSStrike>
29. LFI Suite - Automatic LFI Exploiter (+ Reverse Shell) and Scanner - <https://github.com/D35m0nd142/LFISuite>
30. OneForAll - Powerful subdomain integration tool - <https://github.com/shmilylty/OneForAll/blob/master/docs/en-us/README.md>
31. lazyrecon - automate some tedious tasks of reconnaissance and information gathering <https://github.com/nahamsec/lazyrecon>
32. Nikto - web server scanner - <https://github.com/sullo/nikto>
33. reflector - Burp plugin able to find reflected XSS on page in real-time while browsing on site  <https://github.com/elkokc/reflector>
34. GitHound - GitHound pinpoints exposed API keys on GitHub  - <https://github.com/tillson/git-hound>
35. Firefox Multi-Account Containers extension - use the web with multiple identities or accounts simultaneously - <https://addons.mozilla.org/he/firefox/addon/multi-account-containers/>
36. Nuclei - fast tool for configurable targeted scanning - <https://github.com/projectdiscovery/nuclei>
37. XSSHunter - Website which helps exploring all kinds of XSS vulnerabillities - <https://xsshunter.com/>
38. dotdotslash - Search for Directory Traversal Vulnerabilities - <https://github.com/jcesarstef/dotdotslash>
## Mapping The Application Content

![Mapping](/images/Mapping.png)

### Running your reconnaissance
Creating a bash script which will create eventually a list of possible-alive subdomains, using Amass, Sublist3r,subfinder,assetfinder.
Example : 
- [ ] python sublist3r.py -d target.com -t 50 -p 80,443 -o subdomains1.txt
- [ ] amass enum -passive -d target.com -o subdomains2.txt
- [ ] subfinder -d target.com -o subdomains3.txt
- [ ] assetfinder [--subs-only] target.com -o subdomains4.txt
- [ ] cat subdomains1.txt subdomains2.txt subdomains3.txt subdomains4.txt > subdomains.txt

Another option - Automating the recon procces with one-liner's such as OneForAll and lazyrecon:
- [ ] OneForAll -  python3 oneforall.py --target target.com run
![oneforall](/images/oneforall.png)
- [ ] lazyrecon - ./lazyrecon.sh -d target.com

Now, we have a list of possible alive subdomains of our target at subdomains.txt.
We have to sanitize the list to working subdomains, there are several methods to do so.

- [ ] httprobe - cat subdomains.txt  httprobe
- [ ] aquatone - cat subdomains.txt  aquatone
- [ ] LiveTargetsFinder - python3 liveTargetsFinder.py --target-list subdomains.txt
- [ ] fprobe - cat subdomains.txt   fprobe
- [ ] anti-burl - cat subdomains.txt   anti-burl

- [ ] Test for subdomain takeover using subjack - ./subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl

### Explore Visible Content
- [ ] Configuring BurpSuite with your browser,  passively spider the site
by monitoring and parsing web content processed by the proxy.
- [ ] Install Wappalyzer to fingerprint the website foundations (CMS/Languages) etc..
- [ ] Browse the entire application in the normal way, visiting every link and
URL, Making sure Burp is open.
- [ ] Review the site map generated by the passive spidering.
- [ ] Actively crawl the application - using hakrawler/Burp scan.

### Consult Public Resources
- [ ] Use Waybackurls for hidden indexed content of the target.
- [ ] Using Google Dorks - Cheatsheet - <https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06>
- [ ] Finding Github secrets - git-hound --subdomain-file subdomains.txt
- [ ] Find email addresses using Hunter.io - <https://hunter.io/>
- [ ] Review any published WSDL files found in the target application.

### Discover Hidden Content
- [ ] Review all client-side code to identify any clues about hidden server-side
content, including HTML comments and disabled form elements.
- [ ] Use Fuzzing techniques recursively - ffuf, dirsearch with SecLists content-discovery text files.

### Discover Default Content
- [ ] Running nikto against our target to detect any default or well-known
content that is present - perl nikto.pl -host target.com
- [ ] Verify any potentially interesting findings manually to eliminate any
false positives within the results.

### Test for Debug Parameters
- [ ] Use listings of common debug parameter names (such as debug, test,
hide, and source) and common values (such as true, yes, on, and 1).
- [ ] Review the application’s responses for any anomalies that may indicate
that the added parameter has had an effect on the application’s processing.

## Analyze the Application

![Analyze](/images/Analyze.png)

### Identify Functionality
- [ ] Test the authentication mechanism, map the actions which are available for the user when interacting with the web application.
### Identify Data Entry Points
- [ ] run ParamSpider - python3 paramspider.py --domain target.com --exclude php,jpg,svg --output targetparams.txt
### Identify the Technologies Used
- [ ] Manually with WAPPALYZER / running nikto on the target domain.
- [ ] Check and inspect the headers returned on burpsuite.
- [ ] Map any third-party modules which are been integrated with the target domain.
### Map the Attack Surface
- [ ] Assembling a list of interesting locations which might be vulnerable such as File upload/Contact/Search pages and etc...

## Test Client-Side Controls

![Client](/images/Client.png)

### Test Transmission of Data Via the Client
- [ ] Check for instances within the web application where data is transmitted via hidden form fields, cookies and URL Parameters.
Modify the values in order to exploit relevent functionality.

### Test Client-Side Controls Over User Input
- [ ] Walk through the application source page to identify cases of client-side controls, which could get bypassed easily.

## Test the Authentication Mechanism

![Auth](/images/Auth.png)

### Understand the Mechanism
- [ ] Register to the Web application as a regular user would, inspect the requests of the proccess within burpsuite.
### Test Password Quality
- [ ] Make manipulations on the input so it will bypass the site restrictions, such as using NULL BYTE or using only "SPACE" chars as the password, it might bypass the password by assigning these combinations: "Gal 1234 56 78" and "Gal12345678" to act the same way.
- [ ] Enter long and complex password, and check if the Authentication mechanisem truncates characters from the password.
### Test for Username Enumeration
- [ ] There are several ways to test for usernames already registered within the web application, mostly through error messages presented by the authentication mechanism, this article from owasp includes several useful methods to do so:<https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account>

### Test Resilience to Password Guessing
- [ ] Try brute-forcing with burp intruder on the login page, check whether there is rate-limiting block implemented.
### Test Any Account Recovery Function
- [ ] Testing the password reset functionality, check if there is a way to manipulate the mechanism in order to takeover the account requesting for password reset.
additionally, you can use the password reset page for Mass-Spam into legitimate emails by brute-force when there is no rate-limiting blocks implemented.
combining the brute force attack with unrestricted length input from the user, could even lead to Application DOS.
This can be easily tested by burp intruder.
### Test Any Remember Me Function
- [ ] Check if there are any special cookies asserted to the user by choosing the "Remember me" function, if so, try to change the value of those cookies to take over other accounts.
### Test Any Impersonation Function
- [ ] While testing for passwords by brute-forcing, inspect if there are several users with the same password, which could indicate that the password is being used as "Backdoor password" by the administrators.
### Test Username Uniqueness
- [ ] Try to sign-up with the same username twice, if it succeeds, try to manipulate any password reset/account deletion by inserting the username value, you might takeover the account you impersonated.
### Check for Unsafe Transmission of Credentials
- [ ] Check within burp if there is a login page without HTTPS, if so - it is reportable as P4 Bug, because if there is wire-shark enabled on the same network, the password are being captured on HTTP (Clear-Text) to anyone inspecting the network flow.
### Check for Unsafe Distribution of Credentials
- [ ] Determine whether account activation/registeration link sent via-email is randomly generated, and not time-based.
### Test for Insecure Storage
- [ ] If there is access to hashed passwords, determine whether there are salted.
### Test Any Multistage Mechanisms
- [ ] Try to proceed the authentication stages out of the original order, check for any modification which could bypass the next stage of the proccess.
### Exploit Any Vulnerabilities to Gain Unauthorized Access
- [ ] Use the information gathered on previous steps to try and takeover accounts on the web application.

### Related reports:
- [ ] Account takeover via password reset - <https://medium.com/@khaled.hassan/full-account-takeover-via-reset-password-function-8b6ef15f346f>
- [ ] Possible Authentication Bypass - <https://hackerone.com/reports/209008>
## Test the Session Management Mechanism

![Session](/images/Session.png)

### Understand the Mechanism

### Test Tokens for Meaning

### Test Tokens for Predictability

### Check for Insecure Transmission of Tokens

### Check for Disclosure of Tokens in Logs

### Check Mapping of Tokens to Sessions

### Test Session Termination

### Check for Session Fixation

### Check for CSRF

### Check Cookie Scope

## Test Access Controls

![Controls](/images/Controls.png)

### Understand the Access Control Requirements
- [ ] Re-use the directory fuzzing in previous stages as authenticated user, and as administrator (if presented), determine the functionalities which require you to be authenticated, and try bypassing those by manipulating parameters / going straight into a specific file/page location. 
### Test with Multiple Accounts
- [ ] Use Firefox Multi-Account Containers extension - register with several users and try to access data which should be presented only locally to the specific user.
focus on pages where there are numbers as parameters, such as userid/picture id, which might get manipulated by changing it's value.
this test could be fruitful for IDOR vulnerabilities.
<https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/>
### Test for Insecure Access Control Methods
- [ ] Search for access controls based on request parameters such as url/blabla&admin=true, find those endpoints by looking at the crawling results from previous steps.

### Related Reports:
- [ ] Access control report - <https://hackerone.com/reports/417839>
- [ ] IDOR report - <https://hackerone.com/reports/227522>

## Test for Input-Based Vulnerabilities

![Input](/images/Input.png)

### Fuzz All Request Parameters
- [ ] Fuzz recursively using ffuf/dirsearch/Burp intruder urls which had returned 401/403 response code, in order to find broken access controls and sensitive/hidden information.
ffuf -w /path/to/wordlist -u https://target/FUZZ -maxtime-job 60 -recursion -recursion-depth 3
### SQL Injection
- [ ] Make inputs in order to find error messages which might indicate that SQL injection vulnerabillity exist such as:        ‘

‘--

- [ ] Blind SQLI : 

‘; waitfor delay ‘0:30:0’--

1; waitfor delay ‘0:30:0’--

- [ ] Automation using SQLMAP : python3 sqlmap.py -u "target.com" --batch --banner

### Related Reports:
- [ ] SQLI - <https://hackerone.com/reports/419017>
- [ ] Blind SQLI - <https://hackerone.com/reports/363815>

### XSS and Header Injection
- [ ] Check for input areas where the text is displayed back as output manually, or from the ParamSpider txt file.
- [ ] Inject unique word (like your first name) with the following characters '"<>;, in order to determine if there is encoding/sanitization of those characters.
- [ ] Use burp reflector extension at the crawling stages, you will recieve alerts where there are reflected parameters which allow the special escape characters mentioned above.
![reflector](/images/reflector.png)
- [ ] Automate the injection process by using XSStrike on the specific url.
- [ ] Use https://xsshunter.com/ features in order to test for Blind XSS aswell.

### Related Reports:
- [ ] Reflected XSS - <https://hackerone.com/reports/438240>
- [ ] Blind XSS - <https://hackerone.com/reports/314126>
- [ ] Stored XSS - <https://hackerone.com/reports/485748>
- [ ] DOM XSS - https://hackerone.com/reports/708592
### OS Command Injection

### Path Traversal
- [ ] Check up the ParamSpider txt file, use gf to find the parameters which ends with "file="
- [ ] try Path traversal payloads manually.
- [ ] Automate the proccess with dotdotslah -  dotdotslash.py [-h] --url URL --string STRING [--cookie COOKIE]
 [--depth DEPTH] [--verbose]
![dotdotslash](/images/dotdotslash.png)
 
### Script Injection

### File Inclusion

### Open Redirection
- [ ] Check up the ParamSpider txt file, use gf to find the parameters which ends with "redirect_url","url"
- [ ] Use OpenredirectX on thos urls - python3.7 openredirex.py -l urls.txt -p payloads.txt --keyword FUZZ
![openredirex](/images/openredirex.png)
## Test for Function-Specific Input Vulnerabilities

![Specific](/images/Specific.png)

### Test for SMTP Injection

### Test for Native Software Vulnerabilities

### Test for Integer Vulnerabilities

### Test for Format String Vulnerabilities

### Test for SOAP Injection

### Test for LDAP Injection

### Test for XPath Injection

### Test for Back-End Request Injection

### Test for XXE Injection

## Test for Logic Flaws

![Logic](/images/Logic.png)

### Identify the Key Attack Surface

### Test Multistage Processes

### Test Handling of Incomplete Input

### Test Trust Boundaries

### Test Transaction Logic

## Test for Shared Hosting Vulnerabilities

![Shared](/images/Shared.png)


### Test Segregation in Shared Infrastructures

### Test Segregation Between ASP-Hosted Applications

## Test for Application Server Vulnerabilities

![Server](/images/Server.png)

### Test for Default Credentials

### Test for Default Content

### Test for Dangerous HTTP Methods

### Test for Proxy Functionality

### Test for Virtual Hosting Misconfi guration

### Test for Web Server Software Bugs

### Test for Web Application Firewalling

## Miscellaneous Checks

![Checks](/images/Checks.png)

### Check for DOM-Based Attacks

### Check for Local Privacy Vulnerabilities

### Check for Weak SSL Ciphers

### Check Same-Origin Policy Confi guration

## Follow Up Any Information Leakage

# Thanks for Reading!

## References
1. The Web Application Hackers Handbook 2 - <https://www.oreilly.com/library/view/the-web-application/9781118026472/>


