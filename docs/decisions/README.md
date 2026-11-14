# Decisions

Why AutoPanel is built the way it is: the decisions its code relies on, one page per area. A
comment in the code that says `Decision: docs/decisions/<page>.md#<decision>` points at one of
these. Each decision says what was decided, why, and where it lives in the code. Where a page and
the code disagree, the code is right and the page is fixed.

| Page | What it covers |
| --- | --- |
| [Processes](processes.md) | the gate and the core, the link between them, host commands, who may open the control socket |
| [Routes and domains](routes.md) | a route's host is under a registered domain; removing a domain never strands a route |
| [Services](services.md) | stacks: the compose subset, the review and the apply, a stack's data, the user and the units each runs as, the audit entry that comes first |
| [The admin screen](ui.md) | the tiled widgets, golib's panels and the dock, two panes for a list, access keys instead of help lines, the file browser, the route form's subdomain and domain |
