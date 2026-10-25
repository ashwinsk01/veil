# Security policy

Veil is experimental and has not been independently audited. Don't trust it with real secrets yet.

Only the latest commit on `main` is supported.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a
vulnerability**. Please don't open a public issue for anything that could weaken a secret.

A useful report says:

- what breaks: secrecy, tamper detection, refresh, composed keys, randomness, or the hardening
  around the process;
- the shortest steps, inputs or share files that show it;
- the commit you tested.

This is a one-person project, so replies come as soon as I can manage, not on a schedule. I'll
confirm the report, fix it in private, and credit you when the fix ships, unless you'd rather not
be named.

## What counts

Anything that lets someone:

- learn anything about a secret from fewer than *k* shares;
- change or forge a share without `combine`, `check` or `recover` noticing;
- combine shares across a refresh, or rebuild a secret during one;
- recover a composed key without every factor;
- read a secret from memory, swap, crash dumps, the screen or the keys, in a way the README doesn't
  already describe.

The README documents the known limits: the table in
[What is proven and what is assumed](README.md#what-is-proven-and-what-is-assumed) (the trusted
dealer, permanent hash keys, a noise source's declared min-entropy) and what `write` can't hide.
Confirming one of those is welcome but not new. A way around one that the README doesn't describe
is.
