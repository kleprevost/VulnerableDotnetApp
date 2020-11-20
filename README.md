# About
Vulnerable ASP.net core application

# OWASP top 10 (2017)
### A1 -Injection
- [x] SQL Injection
- [x] XPATH Injection
### A2 -Broken Authentication
- [x] Credential Stuffing
### A3 -Sensitive Data Exposure
- [x] Leaking Credit Card Information
### A4 -XML External Entities (XXE)
- [x] Accessing local resource
### A5 -Broken Access Control
- [x] Elevate access privileges
### A6 -Security Misconfiguration
- [x] Show SQL Exception in response
### A7 -Cross-Site Scripting (XSS)
- [x] Reflected XSS
### A8 -Insecure Deserialization
- [x] Insecure XML deserialization
### A9 -Using Components with Known Vulnerabilities
- [x] Using component vulnerable to XSS
### A10 -Insufficient Logging&Monitoring
- [x] Insufficient logging after data breach

# Installation

You can execute the following commands in order to run the application:

```bash
dotnet build vulnerable_asp_net_core.sln
dotnet run --project vulnerable_asp_net_core
```

After running the application, you should see the following output:

```bash
...
Now listening on: https://localhost:5001
Now listening on: http://localhost:5000
Application started. Press Ctrl+C to shut down.
Application is shutting down...
```

In order to run all exploits you can execute the `run_all.sh` script in the
`exploits/` directory with:

```bash
./run_all.sh
```

The command above should produce the following output:

```bash
execute ./sqlinjection.sh ... OK
execute ./xss.sh ... OK
execute ./vulnerable_component.sh ... OK
execute ./broken_authentication.sh ... OK
execute ./insecure_deserialization.sh ... OK
execute ./security_misconfiguration.sh ... OK
execute ./xxe.sh ... OK
execute ./common.sh ... OK
execute ./xpathinjection.sh ... OK
execute ./broken_access_control.sh ... OK
execute ./insufficient-logging.sh ... OK
execute ./sensitive_data_exposure.sh ... OK
```
