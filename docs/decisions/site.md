# The site

AutoPanel's own site: a home page, a blog and documentation, published from AutoDoc. This page
grows with the feature. So far the rules and the storage exist; nothing is built or served yet.

## A document has one of four levels, and is private unless said

**Decided:** every published document is `public`, `protected`, `internal` or `private`.

| Level | Who may read |
| --- | --- |
| `public` | anyone |
| `protected` | anyone who was given its passphrase |
| `internal` | every member who is signed in |
| `private` | its owner, and the members it is shared with |

- **A first publish that names no level is private.** Publishing by mistake shows a document to
  its author, not to the world.
- **An update that names no level keeps the one it has.** Silence never changes who may read.
- An unknown level is refused, never guessed.
- Only a private document has a share list, of members, never including its owner.

**In the code:** `core/site/doc.go` (`Level`, `Doc.Check`).

## The core owns a document's identity

**Decided:** a document's ID, its owner and its level are the core's records. Nothing a build
writes, and nothing in a published file, is believed about them.

- **The ID is never used again.** A slug may be reused after a removal; the new document has a new
  ID, and nothing that named the old one (a grant, a path) opens the new.
- **The owner is the user who first published it, and never changes.** A user who owns documents
  cannot be removed until the documents are. There is no transfer: a way to give a document
  another owner would be a way to read it.
- **An update cannot move, rename or reassign a document:** it runs in one transaction with the
  read it was decided from, and the store keeps the ID, the site, the slug and the owner whatever
  the update says.
- **Two counters:** the version rises when the content changes; the generation when who may read
  changes (the level, the share list).
- **A site's security generation** rises when a document is taken from public, by a lower level or
  by removal, and at nothing else. Pages built before the change carry the older number and are
  never served again.

**In the code:** `core/site/store.go`, `store/sites.go`, `sql/deployments/*/000010_update_sites.sql`.

## One table of who may do what

**Decided:** reading, listing, changing, protecting and removing a document are decided in one
place (`May`), from the level and from who asks: nobody, a passphrase's grant, a member, the
owner, an administrator.

- **An administrator has no branch for reading.** A private document is its owner's and its share
  list's, as its level says. An administrator can remove any document, and see that it exists.
- A grant opens a protected document and nothing else: not one that has since become internal or
  private.
- A document whose level is not one of the four is nobody's to read.
- A protected document is unlisted: only its owner sees it in a list.

**In the code:** `core/site/access.go`; `core/site/access_test.go` writes the whole table out.

## What a document's files may be

**Decided:** a document's resources (an image it shows, a diagram, a chart, a table) belong to
that one document and are found only by their exact name under it.

- **A name is a relative path, taken byte for byte:** no absolute path, no `.` or `..` part, no
  backslash, no control character, at most six parts and 200 bytes. It is never cleaned into
  another name, so the name that was checked is the name that is served.
- **Names the site makes itself are refused:** a first part that starts with an underscore, and
  `index.html`.
- **Two names that differ only by case cannot both exist,** so a file system that folds case
  cannot serve one as the other.
- **A file is what its name and its first bytes both say:** a PNG, JPEG, WebP or GIF image, a
  Mermaid diagram (`.mmd`), a Vega-Lite chart (`.chart.json`) or a table (`.csv`). A renamed file
  is refused. SVG is not an image here: it can carry script.
- A diagram, a chart or a table asked for directly is plain text to save, never something a
  browser acts on.

**In the code:** `core/site/doc.go` (`ResourceName`), `core/site/resource.go` (`ResourceType`).

## A site's configuration is checked whole

**Decided:** an administrator sets a site's configuration with `site.set`, written in YAML. The
whole configuration is checked before it is stored, and a refused one changes nothing.

- **Unknown keys are refused,** as are a second document and anchors or aliases, so a small file
  cannot expand. The limit is 16 KiB.
- **No value is markup.**
  - A colour is `#` and six hexadecimal digits.
  - `font` is `serif`, `sans` or `mono`, and `width` is `narrow` or `wide`.
  - `logo` is the plain name of an image.
  - `theme` is one the kit ships.
  - Text is printable, on one line, and bounded.
  - A navigation link goes to a path of the site or to an `https://` address with no
    credentials.
- **It is stored as JSON** with its defaults filled in, and that is what the builder is given.
- **A content host is no site's host,** and no other site's content host. A site cannot be added
  on a content host either: an active document there would otherwise run on a page's origin.
- The audit entry says what changed: the configuration, or the content host. It never holds the
  configuration's text.

**In the code:** `core/site/config.go`; `site.set` and `site.get` in `core/site/module.go`.

## What a build wrote is checked before it is served

**Decided:** a build's output is untrusted, because a theme is code and the builder ran it. The
core checks the whole output before any of it is served, and one file that breaks a rule fails
the whole build.

- **It looks before it reads.** It walks the output through a root-scoped handle, looking at each
  entry without following it. A symbolic link, a pipe, a socket or a device fails the build
  before any file is opened. Depth, the number of files, each file's size and the site's total are
  bounded. A hidden name (one starting with `.`) is refused.
- **Only what a site serves:** `.html`, `.css`, `.xml`, `.txt`, PNG, JPEG, WebP and GIF images,
  and WOFF and WOFF2 fonts. Each image and font must start with the bytes its type has.
- **A page is parsed, not searched,** so prose or a code block about `<script>` passes, and markup
  hidden behind entities does not. A page may not hold a script, a style element or attribute, an
  event attribute, a form, a frame, an object, a base, a `meta http-equiv`, MathML, or a `<link>`
  that preloads or connects anywhere.
  - Whatever the browser fetches (an image, a stylesheet, a `srcset`) must be a path of the site.
  - A link may go to a path of the site, or to an `http`, `https` or `mailto` address.
  - The rules apply to addresses as a browser reads them: tabs and newlines removed, entities
    decoded, and `//host` or a backslash taken as another host.
- **The exceptions are exact.**
  - A page the renderer says has a Mermaid diagram may load the kit's two scripts: their own
    paths, with their integrity values, deferred, each once.
  - A document's inert copy (`_doc.html`) is shown in a frame with `sandbox=""`, and only if the
    build made it. The copy may have its own styles.
  - An active document is shown from the content host, in a frame allowed scripts and nothing
    more.
- **Inline SVG is what the chart writer draws:** its shapes, clips, gradients and labels, with
  `url()` only to a fragment of the same drawing. There is no script, `foreignObject`, `use`,
  `image`, link, animation or style. The test fixtures are charts made by golib's own writer
  (`core/site/testdata/charts`).
- **A stylesheet is read as CSS reads it:** comments skipped, and escapes and strings decoded. An
  `@import`, a `url()` that is not a path of the site, and the functions that load without
  `url()` are refused.
- **The feed and the sitemap** must be well formed, with no document type, no instruction other
  than the XML declaration, and only RSS, Atom and sitemap elements.

**In the code:** `core/site/check.go` (the walk), `core/site/check_page.go` (the rules);
`core/site/check_test.go`.

## The new pages replace the old in one system call

**Decided:** a build runs in a work directory beside the live ones, on the same file system.

- **Each build starts empty.** It never sees another build's input, output or scratch. Its input
  is the core's, and only its output directory is the builder's.
- **Once the build has exited, its output is taken away** before anything in it is looked at. The
  work directory becomes the core's, mode `0700`, so no path reaches the output. After the check,
  every entry becomes the core's, `0755` or `0644`, and no link is followed.
- **The swap is one `renameat2` exchange:** a reader gets the old pages or the new ones, never a
  missing directory or a mix. The first build of a site is a rename onto a name nothing holds.
- **The old pages are kept, closed off, until the next build begins,** so a request that opened
  them a moment before the swap still reads them whole.

**In the code:** `host/site/files.go`; `TestTheSwapIsAtomic` reads continuously from four readers
during 100 swaps.

## A build runs as its own user, in a container with no network

**Decided:** the build runs as `ap-site` under that user's own systemd, as a stack's pull does. It
is not a child of the core, so its memory is not counted against the core.

- **The unit is collected when it ends,** its control group killed with it, so nothing the build
  started outlives it and writes to the output after the core has taken it away. The unit has a
  memory ceiling of its own, above the container's.
- **The container:**
  - no network, a read-only root, no capability, no new privilege;
  - at most 512 MB of memory and no swap, 256 processes, 120 seconds, no file over 10 MiB, and
    64 MB of scratch in `/tmp`;
  - the input and a theme read-only; the output is the one place it writes;
  - it never pulls: the image is prepared beforehand, by its digest, and named by digest every time.
- **`site` is no stack's name.** A stack runs as `ap-` and its name, and would get the builder's
  user.

**In the code:** `host/site/builder.go`. `TestARealBuild` runs on the test VM as root with a small
image by digest, and checks from inside the container that the network, a write outside the
output, a write to the input and a file over the limit all fail.

## The audit log names a document, never its text

**Decided:** every change to a site or a document has its entry, written in the change's own
transaction: the site's host and the document's slug, and its level before and after. Never a
title, a body or front matter.
