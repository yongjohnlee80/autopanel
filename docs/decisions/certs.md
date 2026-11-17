# Certificates

How AutoPanel obtains certificates, when it renews them, and what it tells the administrator about
them.

## Obtained at the first request, for a name a route holds

**Decided:** a certificate is ordered when the first HTTPS request for a name arrives, and only for
a name a route holds (or the mail host). A request for any other name gets no certificate and
orders none.

**Why:** a stranger can open a TLS connection with any name. If that ordered a certificate, anyone
could spend the server's rate limits at the certificate service.

**A wildcard** cannot be ordered at a request, so wildcard names are obtained and renewed in the
background, and need the DNS challenge.

**In the code:** `internal/certs/certs.go` (`decide`, `For`, `Manage`),
`TestOnlyARoutedHostMayHaveACertificate`.

## Renewed at a request, in the last third of its life

**Decided:** a certificate is renewed when a request for its name arrives during the last third of
its life (the last 30 days of a 90-day certificate). The request is served with the certificate
there is; the new one is ordered beside it.

**Earlier when the certificate service asks.** A service that publishes renewal information (ARI)
may name an earlier time; the renewal then starts at that time's next request. The panel's
"renewing" state is the last third, whatever the service suggests.

**The gate asks the core for a name's certificate once an hour,** so a renewal starts within an
hour of the window opening on a busy name, and a renewed certificate is served within an hour of
being obtained.

**Past its end,** the next request waits for a new certificate (a second or two) and is served
with it.

**What follows:** a name that gets no request is not renewed. Its certificate expires quietly, and
the first request after that waits for a new one. Nothing is lost by it: a name nobody asks for
serves nobody.

**In the code:** CertMagic's on-demand renewal; `internal/certs/certs.go` (`Stored` computes the
same window for the panel).

## What the panel shows

**Decided:** **Certs → Certificates** (`certs.list`) lists every name a route holds, and the mail
host, with the certificate the store holds for it under the certificate service in use:

| State | Means |
| --- | --- |
| none yet | none stored: the first HTTPS request for the name orders one |
| valid | stored, and not yet in its last third |
| renewing | in its last third: the next request renews it |
| expired | past its end: the next request must obtain one first |
| unknown | the store could not be read (the vault is locked) |

Beside the state: who issued it, when it expires, when its last third begins, and the reason the
last order for the name failed, with its time.

**Reading orders nothing.** The list reads the store. It never asks the certificate service for
anything, so opening the panel cannot spend a rate limit.

**Under the service in use.** Staging and production certificates are kept apart. After a switch
to production, a name shows "none yet" until its first request, though its staging certificate is
still in the store.

**The last failure is kept in memory,** not in the store: it is gone after a restart, and cleared
when an order for the name succeeds. The audit log keeps the history.

**In the code:** `app/certstatus.go` (`rows`, `certState`), `internal/certs/certs.go` (`Stored`),
`internal/ui/monitor.go` (`certDetail`); `TestStoredReadsTheStoreAndOrdersNothing`,
`TestACertificatesState`, `TestCertificatesPanel`.

## Every order is in the audit log

**Decided:** each order's end is an audit entry by `autopanel`: `certs.obtained`, `certs.renewed`
or `certs.failed`, with the name, and for a failure the reason.

**A name that keeps failing is written once an hour,** or at once when the reason changes: a
failing name is tried again at each request, which can be every few seconds, and the log must not
fill with one fact.

**In the code:** `app/certstatus.go` (`certEvents`), `internal/certs/certs.go` (`onEvent`);
`TestOrdersAreAuditedAndARepeatedFailureOnceAnHour`, `TestAnOrdersEndIsTold`.

## Host checks

**Decided:** two findings in **System → Host checks**:

| Check | Severity | Holds when |
| --- | --- | --- |
| `cert-expiring` | alert | a certificate has expired, or is within 7 days of its end |
| `cert-failing` | notice | the last order for a name failed, and its certificate is not that close to its end |

**Why 7 days:** a renewal starts 30 days before the end. A certificate that reaches its last week
has had three weeks of requests that did not renew it, or none at all; either is worth a look. A
certificate that renews in time never shows.

**In the code:** `app/certstatus.go` (`certChecks`), `TestCertificateChecks`.
