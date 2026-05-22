# GPON Default Credentials Attack

**Analyst Name:** Jalen Fairchild  
**Date of Analysis:** 5/21/2026  
**Time and Date of Activity:** May 15, 2026 23:03:58 UTC  

---

## Executive Summary

An external automated scanner initiated a connection to the honeypot's SSH listening port. The client identified itself using a Go-based SSH implementation (`SSH-2.0-Go`) and immediately attempted to pass default credentials for Gigabit Passive Optical Network (GPON) home routers and modems (`AdminGPON` / `ALC#FGU`). The connection was safely closed by the honeypot architecture after 1 second following the failed authentication sequence.

### Relevant Logs
These logs show the failed connection attempt:

> 2026-05-15T23:03:58.414374Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 45.148.10.121:59460 (192.168.1.171:2222) [session: 427188cbb3b1]
> 2026-05-15T23:03:58.421654Z [HoneyPotSSHTransport,4,45.148.10.121] Remote SSH version: SSH-2.0-Go
> 2026-05-15T23:03:58.556939Z [HoneyPotSSHTransport,4,45.148.10.121] SSH client hassh fingerprint: bf7dbf67fa9b26ee9f9deb99c49320ba
> 2026-05-15T23:03:58.569642Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256' key alg=b'ecdsa-sha2-nistp256'
> 2026-05-15T23:03:58.570248Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes128-ctr' b'hmac-sha2-512' b'none'
> 2026-05-15T23:03:58.570762Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes128-ctr' b'hmac-sha2-512' b'none'
> 2026-05-15T23:03:58.690991Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] NEW KEYS
> 2026-05-15T23:03:58.692570Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
> 2026-05-15T23:03:58.813457Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'AdminGPON' trying auth b'none'
> 2026-05-15T23:03:58.931457Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'AdminGPON' trying auth b'password'
> 2026-05-15T23:03:58.935891Z [HoneyPotSSHTransport,4,45.148.10.121] login attempt: 23
> 2026-05-15T23:03:58.936660Z [HoneyPotSSHTransport,4,45.148.10.121] login return, expect: [b'root'/b'root']
> 2026-05-15T23:03:58.952802Z [HoneyPotSSHTransport,4,45.148.10.121] login attempt [b'AdminGPON'/b'ALC#FGU'] failed
> 2026-05-15T23:03:59.961846Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'AdminGPON' failed auth b'password'
> 2026-05-15T23:03:59.962801Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] unauthorized login: ()
> 2026-05-15T23:04:00.082306Z [cowrie.ssh.transport.HoneyPotSSHTransport#info] connection lost
> 2026-05-15T23:04:00.083105Z [HoneyPotSSHTransport,4,45.148.10.121] Connection lost after 1 seconds

* **Source IP:** `45.148.10.121`
* **Credentials Attempted (username/password):** `AdminGPON` / `ALC#FGU`

---

## Vulnerability & Exploit Analysis

This attack attempted to exploit default credentials of GPON edge devices. If accessed, these devices have known vulnerabilities such as command injection and authentication bypass as seen here:

* **CVE-2018-10561 [1]:** It is possible to bypass authentication simply by appending `?images` to any URL of the device that requires authentication, as demonstrated by the `/menu.html?images/` or `/GponForm/diag_FORM?images/` URI. One can then manage the device.
* **CVE-2018-10562 [2]:** Command Injection can occur via the `dest_host` parameter in a `diag_action=ping` request to a `GponForm/diag_Form` URI. Because the router saves ping results in `/tmp` and transmits them to the user when the user revisits `/diag.html`, it's quite simple to execute commands and retrieve their output.

### MITRE ATT&CK Techniques

This activity is related to several MITRE ATT&CK Techniques:

* **T1595.001 – Reconnaissance: Active Scanning [3]:** The automated node scans public IPv4 address space continuously to map open entry points.
* **T1110.001 – Credential Access: Brute Force [4]:** The script executes a programmatic authentication attempt using a known, pre-compiled pair of device-specific credentials.

---

## Attacker Goal & Likelihood of Success

### Goal of the Attack:
The goal of this specific interaction is IoT Botnet Recruitment. Threat actors scan public IP ranges to compromise consumer edge routers. Once authenticated, the botnet runs automated scripts to disable local firewall security logs, download malicious ELF executable scripts, and transform the router hardware into a slave node. This node is then leveraged globally to execute massive Distributed Denial of Service (DDoS) campaigns or route secondary malicious traffic through clean residential IP spaces.

### Likelihood of Success:
If this attack was executed against a factory-configured GPON residential modem, the exploit would have a 100 percent success rate, giving root shell access to the attacker without giving an alert.

---

## Defensive Recommendations

To protect a system from this attack:

* Change default manufacturer usernames and passwords to complex, unique strings immediately during initial setup before the hardware ever touches a live internet connection.
* Turn off all public, internet-facing remote access for SSH and HTTP portals on the router's external interface so the port is completely hidden from scanners.

---

## Threat Intelligence & Indicators

### About the Attacker:
The IP `45.148.10.121` is from the Netherlands owned by Techoff SRV Limited. It is known to make many unauthorized ssh login attempts [5][6].

### Indicators of Compromise (IoCs):
* **IP Address:** `45.148.10.121`
* **SSH Client Hash Fingerprint:** `bf7dbf67fa9b26ee9f9deb99c49320ba`

---

## External References

* [1] https://nvd.nist.gov/vuln/detail/cve-2018-10561
* [2] https://nvd.nist.gov/vuln/detail/CVE-2018-10562
* [3] https://attack.mitre.org/techniques/T1595/001/
* [4] https://attack.mitre.org/techniques/T1110/
* [5] https://www.abuseipdb.com/check/45.148.10.121
* [6] https://www.shodan.io/host/45.148.10.121
