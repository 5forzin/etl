# Security

ETL is experimental and has not had an independent security audit. Do not rely
on it for anonymity or system-wide traffic protection.

TLS 1.3 and certificate verification protect the tunnel. Authentication precedes
destination DNS and dialing. The server blocks private and special-use addresses,
checks every DNS result, and connects to validated numeric addresses. Setup
deadlines, frame bounds, idle limits and connection caps constrain resource use.

The local proxy has no authentication; other processes on the machine can use it.
Each server has one shared token. Rotation affects new sessions; a restart ends
existing ones. Windows DPAPI protects stored tokens for the current user, not
against another process with that user's privileges.

The access network can see the tunnel endpoint and traffic patterns. The server
and hosting provider remain trusted parties. Traffic beyond the exit needs its
own application encryption. Local DNS, UDP and WebRTC are outside this TCP proxy.

Report vulnerabilities through
[GitHub private reporting](https://github.com/5forzin/etl/security/advisories/new).
If that channel is unavailable, request a private contact in an issue without
publishing exploit details. Exclude tokens, private keys, personal traffic and
unredacted captures from reports.
