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
  read it was decided from, and the store keeps the ID, the site, the folder, the slug and the
  owner whatever the update says. Moving is its own verb (below).
- **Two counters:** the version rises when the content changes; the generation when who may read
  changes (the level, the share list).
- **A site's security generation** rises when something is taken from public, by a lower level, a
  removal or a move out of the public, and at nothing else. Pages built before the change carry the older number and are
  never served again.

**In the code:** `core/site/store.go`, `store/sites.go`, `sql/deployments/*/000010_update_sites.sql`.

## A site is a tree of folders and documents

**Decided:** everything on a site is a node, either a folder or a document. Folders nest, and
each site has one root folder.

- **A node's address is its path:** the slugs of its folders and its own, such as
  `/guides/install/linux/`. A slug is unique among its siblings, folders and documents together.
  Folders nest at most 8 deep, a folder holds at most 1,000 nodes, and an address is at most
  255 bytes.
- **A folder has a level, like a document, and a node is no more open than the most closed folder
  above it.** To read a node you must be allowed it and every folder above it. A public document
  in an internal folder is internal. A passphrase for a protected folder opens what it holds that
  is public; a protected node inside it needs its own passphrase too.
- **Lists are filtered node by node.** A folder you may not read is, to you, no folder at all.
- **Who puts things where:** anyone who may publish can put things at the root. Inside a folder,
  only its owner and an administrator can.
  - `parents: true` makes the missing folders of a path, private and yours, and only where you
    may put things.
- **A folder is removed only when empty.** The root is never changed, moved or removed.
- **A move is checked whole.** A folder can't move into itself or under itself, and everything it
  carries must stay within the depth and address limits. Moving anything public out of the public
  takes the public pages down first, as lowering a level does.
- **The public build** gets the nodes that are public along their whole path. A folder's page lists
  its public children.

**In the code:** `core/site/tree.go` (the verbs `site.folder.*`, `site.node.list`,
`site.node.move`), `MayAt` and `MayPutIn` in `core/site/access.go`, `Move` in `store/sites.go`.

## One table of who may do what

**Decided:** reading, listing, changing, protecting and removing a document are decided in one
place (`May`), from the level and from who asks: nobody, a passphrase's grant, a member, the
owner, an administrator.

- **An administrator reads everything on the site,** at every level, page and source: they answer
  for what the site holds, legally too. Each read that only the role allows is written to the
  audit log before anything is shown, naming the document and never its text; if the entry
  cannot be written, nothing is shown. An administrator can remove any document, and changes none
  that is not theirs.
- A grant opens a protected document and nothing else: not one that has since become internal or
  private.
- A document whose level is not one of the four is nobody's to read.
- A protected document is unlisted: only its owner, and an administrator, see it in a list.

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
  event attribute, a form, an input other than a task list's disabled checkbox, a frame, an
  object, a base, a `meta http-equiv`, MathML, or a `<link>` that preloads or connects anywhere.
  - Whatever the browser fetches (an image, a stylesheet, a `srcset`) must be a path of the site.
  - A link may go to a path of the site, or to an `http`, `https` or `mailto` address.
  - The rules apply to addresses as a browser reads them: tabs and newlines removed, entities
    decoded, and `//host` or a backslash taken as another host.
- **The exceptions are exact.**
  - A page the renderer says has a Mermaid diagram may load the kit's two scripts: their own
    paths, with their integrity values, deferred, each once. The two are in the binary (Mermaid
    12.1.0 as AutoDoc's export vendors it, pinned by its tarball's integrity, and the start that
    draws a page's diagrams): `--site-build` writes them into the output at `/_kit/`, and the core
    takes their integrity from its own copy. A core and a kit image of different releases fail
    closed: the check does not know the other's scripts.
  - A document's inert copy (`_doc.html`) is shown in a frame with `sandbox=""`, and only if the
    build made it. The copy may have its own styles.
  - An active document is shown from the content host, in a frame allowed scripts and nothing
    more.
- **Inline SVG is what the chart writers draw:** its shapes, clips, gradients and labels (placed
  by `text-anchor` and a central baseline), with `url()` only to a fragment of the same drawing.
  There is no script, `foreignObject`, `use`, `image`, link, animation or style. The test fixtures
  are charts made by golib's own writers (`core/site/testdata/charts`, and each fixture spec drawn
  by `chart/vegalite`, the renderer's).
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
transaction: the site's host and the node's path, and its level before and after. Never a
title, a body or front matter.

## The serving process reads files and decides nothing else

**Decided:** `autopanel --site` serves every site's live pages on a unix socket for the gate. It
holds no secret, and it decides nothing but which file a request names.

- **`GET` and `HEAD` only;** any other method is `405`. A hidden name, a path outside the site, a
  host with no site and a type outside the output check's list are all `404`.
- **Each request opens the site's directory once** and reads the page and the core's manifest
  through that one handle. A swap between the two cannot give a page the policy of another build.
- **The manifest is the core's,** written after the check. It is a hidden file, which the output
  check refuses in a build's output and the server never serves. It names the pages that may load
  the kit's scripts, and the content host.
- **Each response class has one policy.**
  - A page: `default-src 'none'`, its own styles, images and fonts, frames of itself and the
    content host, no framing, no base, no form.
  - A diagram page: the same, plus `script-src` with the kit's two hashes.
  - An inert document: `sandbox`.
  - Every answer, a refusal included, carries `nosniff` and `no-referrer`.
- Ranges, conditional requests and `HEAD` are HTTP's own (`http.ServeContent`). Pages are cached
  for 5 minutes, refusals not at all. Nothing is logged per request.

**In the code:** `host/site/serve.go`, `app/sitemain.go`.

## A build sees public documents only, and is one of a kind at a time

**Decided:** the core builds a site's public pages from its public documents, one build at a time
on the host. A build starts two seconds after the last change, so an article and its ten images
are one build.

- **The input is a snapshot of public documents.** A held document's text, files and front
  matter are in no build's input. The snapshot names each source and file by its digest. If one
  has changed by the time it is read, the build is superseded, never a mix, and the build
  already owed reads the change.
- **The core chooses each page's path,** and gives it to the kit in `build.json`.
- **The core decides which pages draw diagrams,** from its own reading of the sources: a
  `mermaid` fence, or a `.mmd` among the document's files. Only those pages may load the kit's
  scripts, by the output check and by the page's policy.
- **Withdrawing something public takes the pages down before the publish answers:** a level
  lowered, or a public document removed. Every path of the site answers `503` until a build
  passes. A theme may have copied the text anywhere, so none of the old pages is served. A build
  that was running when the withdrawal happened carries the old security generation, and is
  discarded.
- **A failed build leaves what was served,** or leaves the site down if it was down, and its
  reason is kept. Publishing again asks for a new build. When the core starts, it runs every build
  that is owed.
- **`site.status`** answers `build` (the newest asked for), `live_build` (the one served),
  `state` (`waiting`, `building`, `live`, `failed` or `down`) and the last failure. A change made
  in build N is live once `live_build` is N or more.

**In the code:** `core/site/build.go`, `app/sitebuild.go`; `core/site/build_test.go`.

## The gate reaches a site through a route only the core makes

**Decided:** each site is a route in the gate's table that the core makes and never stores. Its
upstream is `site:`, which the gate serves from the serving process's socket. The gate learns
that socket's path when it starts, never from a route.

- **A stored route cannot be a site's.** `site:` is accepted only on a route the core made (a
  negative ID; a stored route's is positive), and only with the path `/`. So no route can name a
  socket, edit a site's route or outlive its site.
- **A site's host is its own.** No stored route may hold a site's host or content host, and a site
  cannot take a host that a route, the mail host or the API holds. Because the table holds the
  site's host, the site's certificate works as any route's does.
- **The serving process runs as `autopanel-site`,** never in the gate's group, which reaches the
  core's link socket. Its socket is in `/run/autopanel-site`, a directory that belongs to the
  gate's group, mode `2750`: the gate can pass through it and nobody else can, and the socket
  takes that group, mode `0660`.
- **The gate holds a site's connections as an upstream's:** the same fixed buffers, a dial
  timeout, the in-flight cap, and an idle pool of 8 that the memory ledger counts.
- **An upgrade stops the serving process with the gate,** so the core starts both again on the new
  binary.
- **Its unit** (`deploy/autopanel-site.service`): no network but loopback, only unix sockets, a
  read-only root, the pages read-only, the core's state and keys out of reach, no capability,
  64 tasks, and 24 MB of memory. The core starts it while a site exists and stops it after the last one goes.
  A core that is down leaves the pages served.
- **The pages are in `/var/lib/autopanel-site`,** not under the core's own state, which the
  serving process must not be able to enter.

**In the code:** `SiteRoute` and `IsSite` in `core/gate/route.go`, the site transport in
`host/gate/gate.go`, `app/siteconf.go`, `deploy/autopanel-site.service`, `install.sh`.
`TestASitesRouteIsServedFromItsSocket` serves a route from a real unix socket. On the test VM the
unit served the gate's user and refused another, with only a loopback interface and about 4 MB of
memory.

## The site kit: Astro, in an image of its own

**Decided:** a site's pages are laid out by the site kit, an Astro project in `site/`. It runs in
the builder's container, from an image pinned by digest (`site/Containerfile`).

- **Its inputs are the core's:** `/input/site.json` (the configuration), `/input/build.json` (the
  public folders and documents, at the paths the core chose, and the site's host), and each
  document's source and files. The input is mounted outside the project, so Astro never reads it
  as content of its own.
- **`autopanel --site-build` is the container's entrypoint.** It renders each body into a fragment
  on the scratch, then runs Astro.
- **A Markdown body (md, xmd) is rendered by AutoDoc's `Fragment`** (`core/export`): the body
  alone, with no page, no inline script and no stylesheet. Raw HTML in the Markdown is escaped.
  - **Its embeds** (a diagram, a chart, a table, an image) are read from the document's own files
    and nowhere else.
  - **Every URL goes through the site's rule:** a fragment, a path on the site, or an `http`,
    `https` or `mailto` address; anything else (`javascript:`, `data:`, `//host`, a backslash or
    a control character) is dropped, a link keeping its text and an image its alt.
  - **A chart is inline SVG** drawn by golib's `chart/vegalite` (no GUI, no cgo, no fonts: labels
    are measured by an approximation of a sans-serif); one it cannot draw stays its source.
  - **The bounds that are AutoPanel's:** 50 diagrams and charts a document, 64 KiB a Mermaid
    diagram's source, 256 KiB a chart's spec, 4 MiB a rendered body; past any, the build fails and
    names the document. A table's (1,000 rows shown) and an embed's (1 MiB) are `Fragment`'s.
  - **An `.html` document is shown as an inert copy,** in a frame that allows nothing
    (`sandbox=""`). The copy is made by a list of what is kept:
    - kept: text, headings, lists, tables, quotes, code, images of this site, the document's own
      styles (a style sheet or a `style` attribute the output check's CSS rule passes);
    - removed with what they hold: scripts, frames, objects, a form's controls, audio and video,
      SVG and MathML, `<link>`, `<meta>` and `<base>`;
    - removed, keeping what they hold: any other element the list does not name;
    - removed: event attributes, and every attribute not listed for its element.
    - **A link works only inside the document** (`#…`). The frame may go nowhere, so any other
      address is moved to the link's `title`, where a reader can read it.
    - The frame takes most of the window's height: without a script it cannot fit itself to what
      it holds.
  - **An active `.html` document runs its scripts, from the content host only.** `active: true`
    at publish; public documents only.
    - Its page on the site holds a frame of `https://<content host>/<address>/` with
      `sandbox="allow-scripts"`: the document has no origin, so it reads no page, cookie or
      storage of the site's.
    - The content host serves the document as it was published, and nothing else of the site. It
      sets no cookie and answers with
      `Content-Security-Policy: sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors https://<site host>`,
      on a direct load as in a frame. So the document loads nothing from anywhere: its scripts,
      styles and images are its own, inline.
    - The build puts each active document under `_active/`, and the output check passes a file
      there only when it is, byte for byte, what the core holds. The site's own host serves
      nothing under `_active/`.
    - **A site needs a content host first** (`site.set` with `content_host`): without one an
      active document is refused, and the content host is not cleared while a document needs it.
    - A script can still navigate its own frame, and so send what it holds elsewhere. What it
      holds is the document, which is public.
- **What it makes:**
  - the home page, a page at each document's and each folder's address, and a folder's page
    listing its public children;
  - `feed.xml`, `sitemap.xml` and `robots.txt`;
  - `look.css`, CSS variables made from the configuration's checked values.
- **Pages carry no script and no style of their own:** `inlineStylesheets: 'never'`, and Astro's own
  content security policy is off (it would be a `<meta http-equiv>`). The serving process sets the
  policy as a header.
- **The image:**
  - Its bases are pinned by digest and taken only once they're a week old.
  - Astro is pinned to an exact version.
  - `npm ci` runs with install scripts off.
  - The final stage has no npm, npx, corepack, yarn, curl or git.
- **Astro's compiler runs as WebAssembly.** Its native build needs AVX2: on a server without it (an
  Ivy Bridge Xeon, an `x86-64-v2` VM) it dies with an illegal instruction as it loads. So the
  native build is removed from the image and the WebAssembly build is used.
- The project is read-only in the container. Astro's generated types go to a small scratch of
  their own (`/site/.astro`), its cache to `/tmp`.

**In the code:** `site/`, `app/sitekit.go`. `TestTheKitBuildsASite` runs as root on the test VM with
the image built there. It publishes through the verbs, builds in the container, checks the output,
swaps it live and reads it from the serving process. A private document is nowhere in it.
