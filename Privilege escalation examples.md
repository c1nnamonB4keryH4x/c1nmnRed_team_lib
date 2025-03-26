Privilege escalation examples
The types of privelege esclation can be broadly classified into two categories: vertical and lateral. Vertical privelege esclation involves gaining higher-level access within the same system or application, while lateral privelege esclation involves moving laterally across different systems or networks to gain access to resources. Below are examples of both types, including real-world examples, detailed analyses, and references to the MITRE ATT&CK framework and OWASP Top 10.

### **Vertical Privelege Esclation**

#### **Example 1: Misconfigured SUID Bit on Linux**

##### **Vulnerable Code Example:**
```bash
#!/bin/bash

# A script that runs with elevated privileges
echo "Running command as user: $(whoami)"
$1  # Executes user-provided command without validation
```
**Analysis:**
- If this script is set with the SUID bit, any user can execute it with root privileges.
- **MITRE ATT&CK Reference:** This vulnerability can be exploited using techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **Real-World Example:** The CVE-2016-5195 vulnerability (also known as "Dirty Cow") exploited a race condition in the Linux kernel to escalate privileges.
- **OWASP Top 10 Reference:** This vulnerability falls under **A5:2021 - Security Misconfiguration**.

##### **Exploit Code Example:**
```bash
# Hypothetical command to escalate privileges
echo "Attacker's command" | ./vulnerable_script.sh
```
**Analysis:**
- The injected command `echo "Attacker's command"` can be used to execute arbitrary commands with elevated privileges.
- **MITRE ATT&CK Reference:** This exploit can be used to achieve **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This exploit falls under **A5:2021 - Security Misconfiguration**.

#### **Example 2: Windows Service Misconfiguration**

##### **Vulnerable Code Example:**
```powershell
# A PowerShell script that runs as a service
Start-Service -Name "VulnerableService"
```
**Analysis:**
- If a Windows service is configured to run with SYSTEM privileges and allows unprivileged users to modify its executable, an attacker can replace the executable with malicious code.
- **MITRE ATT&CK Reference:** This vulnerability can be exploited using techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **Real-World Example:** The CVE-2017-0144 vulnerability exploited by the WannaCry ransomware used a similar technique to escalate privileges.
- **OWASP Top 10 Reference:** This vulnerability falls under **A5:2021 - Security Misconfiguration**.

##### **Exploit Code Example:**
```powershell
# Replace the service executable with a malicious payload
copy malicious.exe "C:\Path\To\Service\VulnerableService.exe"
```
**Analysis:**
- The injected command `copy malicious.exe "C:\Path\To\Service\VulnerableService.exe"` can be used to replace the service executable with malicious code, leading to full system compromise.
- **MITRE ATT&CK Reference:** This exploit can be used to achieve **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This exploit falls under **A5:2021 - Security Misconfiguration**.

### **Lateral Privelege Esclation**

#### **Example: Mimikatz Usage**

##### **Vulnerable Code Example:**
```powershell
# PowerShell command to dump credentials
Invoke-Mimikatz -Command "sekurlsa::minidump C:\Path\To\Memory.dmp"
```
**Analysis:**
- An attacker with access to a low-privileged account can use tools like Mimikatz to dump credentials from memory and gain access to other accounts.
- **MITRE ATT&CK Reference:** This vulnerability can be exploited using techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **Real-World Example:** The CVE-2017-0143 vulnerability exploited by the EternalBlue exploit allowed attackers to move laterally within a network.
- **OWASP Top 10 Reference:** This vulnerability falls under **A5:2021 - Security Misconfiguration**.

##### **Exploit Code Example:**
```powershell
# Hypothetical command to escalate privileges laterally
Invoke-Mimikatz -Command "sekurlsa::minidump C:\Path\To\Memory.dmp"
```
**Analysis:**
- The injected command `Invoke-Mimikatz -Command "sekurlsa::minidump C:\Path\To\Memory.dmp"` can be used to dump credentials from memory, leading to unauthorized access to sensitive resources across the network.
- **MITRE ATT&CK Reference:** This exploit can be used to achieve **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This exploit falls under **A5:2021 - Security Misconfiguration**.

### **Defensive Measures & Mitigations**

#### **Implementing Least Privilege Principle**
- Ensure that users and applications have the minimum level of access necessary to perform their functions.
- **MITRE ATT&CK Reference:** This mitigation can defend against techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This mitigation falls under **A5:2021 - Security Misconfiguration**.

#### **Regular Security Audits**
- Conduct regular audits of user accounts, permissions, and configurations to identify and remediate potential vulnerabilities.
- **MITRE ATT&CK Reference:** This mitigation can defend against techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This mitigation falls under **A5:2021 - Security Misconfiguration**.

#### **Patch Management**
- Keep systems and applications up to date with the latest security patches to mitigate known vulnerabilities.
- **MITRE ATT&CK Reference:** This mitigation can defend against techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This mitigation falls under **A5:2021 - Security Misconfiguration**.

#### **User Education and Awareness**
- Train users to recognize phishing attempts and other social engineering tactics that could lead to privilege escalation.
- **MITRE ATT&CK Reference:** This mitigation can defend against techniques such as **T1055 (Process Injection)** and **T1059 (Command and Scripting Interpreter)**.
- **OWASP Top 10 Reference:** This mitigation falls under **A5:2021 - Security Misconfiguration**.

### **Conclusion**

These enhanced examples provide a comprehensive understanding of privilege escalation techniques, including both vertical and lateral escalation scenarios. By incorporating real-world examples and specific vulnerabilities, we can better prepare for potential attacks and develop effective defenses. Each example includes references to the MITRE ATT&CK framework and OWASP Top 10, ensuring a thorough understanding of the security landscape. If you need further details or specific examples for any section, feel free to ask!