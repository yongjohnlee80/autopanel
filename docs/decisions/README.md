# Decisions

Why AutoPanel is built the way it is: the decisions its code relies on, one page per area. A
comment in the code that says `Decision: docs/decisions/<page>.md#<decision>` points at one of
these. Each decision says what was decided, why, and where it lives in the code. Where a page and
the code disagree, the code is right and the page is fixed.

| Page | What it covers |
| --- | --- |
| [Processes](processes.md) | the gate and the core, the link between them, host commands, who may open the control socket |
| [Routes and domains](routes.md) | a route's host is under a registered domain; removing a domain never strands a route |
| [Certificates](certs.md) | obtained at the first request for a name a route holds, renewed at a request in the last third; what the panel shows without ordering anything; orders in the audit log; host checks |
| [Services](services.md) | stacks: the compose subset, the review and the apply, a stack's data, the user and the units each runs as, the audit entry that comes first |
| [The firewall](firewall.md) | the manager the host has, read and driven, never a ruleset of AutoPanel's; each port's verdict; the lockout guard and the enable that undoes itself; rules a stack or mail owns; the commands where AutoPanel will not act; host checks; the installer's step |
| [Port forwards](forwards.md) | a public TCP port sent to a literal target; what a forward may never do (SSH, mail's inner ports, a host name); reviewed then applied; the firewall rule it owns; the limits |
| [Mail](mail.md) | Stalwart as a stack behind the gate: the gate forwards the mail ports with a PROXY header, and only the gate can reach them |
| [The HTTPS API](api.md) | served by the gate on a host of its own, to API tokens; the core decides and still listens on no network; one answer without a token; what is public; the limits and the sum behind them |
| [The gate's limits](limits.md) | every part of the gate bounded and the unit's memory limit their sum; fixed socket buffers and wider ones for a few large transfers; requests in flight and connections; a request that stops moving |
| [The site](site.md) | a tree of folders and documents; four levels, private unless said; the core owns a document's identity; one table of who may do what, an administrator reads everything, audited; what a document's files may be |
| [Users and roles](auth.md) | four roles checked on every call, only admins hold the master key, two-factor with one answer for every failure, login limits, sessions, API tokens |
| [The admin screen](ui.md) | the tiled widgets, golib's panels and the dock, two panes for a list, access keys instead of help lines, the file browser, the route form's subdomain and domain |
