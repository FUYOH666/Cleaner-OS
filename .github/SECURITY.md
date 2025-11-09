# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

Please report (suspected) security vulnerabilities to **[security@scanovich.ai](mailto:security@scanovich.ai)**. You will receive a response within 48 hours. If the issue is confirmed, we will release a patch as soon as possible depending on complexity but historically within a few days.

Please include the following information in your report:
- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

## Security Best Practices

When using Cleaner-OS:
- Always run with appropriate permissions
- Review the files that will be deleted before confirming
- Keep your Python dependencies up to date
- Use virtual environments to isolate dependencies
- Regularly audit your system for security issues

## Disclosure Policy

When we receive a security bug report, we will assign it to a primary handler. This person will coordinate the fix and release process, involving the following steps:

1. Confirm the problem and determine the affected versions.
2. Audit code to find any potential similar problems.
3. Prepare fixes for all releases still under maintenance. These fixes will be released as fast as possible to the repository.

## Recognition

We recognize security researchers who responsibly disclose security vulnerabilities. If you would like to be recognized, please let us know in your report.

