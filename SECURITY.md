# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it, and what an attacker could do with it. We'll acknowledge the report, keep you updated while we work on a fix, and credit you in the advisory unless you'd rather we didn't.

## Supported versions

Fixes go into the latest release. Upgrade to it to get them (SelfHosting.md, "Upgrading").

## Scope

In scope: this repository's code, infrastructure modules and documented deployment. That includes the login and OAuth/OIDC endpoints, the Admin API, the CLI, background jobs and the build pipeline.

Out of scope: weaknesses in a particular deployment's own configuration, such as overly broad IAM access to the Admin API, and denial of service by volume. Please don't test against deployments you don't operate.

ThreatModel.md describes what LiteLogin defends against, and the risks it accepts.
