# Malware IOCs and TTPs of various threat actors
Selected set of IOCs released by Ebryx DFIR team working on CA/Incident Response assignments 

>Repository Structure

- The root directory contains sub-directories with each sub-directory representing a single threat actor
- Each sub-directory contains the following text files:
    
    1. `domains.txt` - a list of domain name IOC
    2. `hashes.txt` - a list of file hash IOC
    3. `ips.txt` - a list of IP address IOC
    4. `yara.yar` - Yara rules

- Each line contains a single IOC entry structured as follows:

    1. `<domain_name>;<description>`
    
        Example:
        ```
        c5918c1c684c5dd20f039fb3442638a98d4e139936336d64b2accdeed7558390;Spear-phishing document targetting British Aerospace Systems
        ```

    2. `<hash>;<description>`
        
        Example:
        ```
        channel.jetos.com;FASTCash campaign - Deltacharlie DDos Tool
        ```

    3. `<IP_address>;<description>`

        Example:
        ```
        45.32.114.96;SkypeJob - Lazarus activity in Chilean Redbanc and Pakistan
        ```