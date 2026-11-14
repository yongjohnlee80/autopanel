# The admin screen

How the terminal admin screen (`autopanel --ui`) is laid out, and why it looks the way it does.

## The main screen is tiled widgets

**Decided:** the main screen is a set of widgets that share the window, each a tile of golib's
`TileManager`: Host (CPU, memory, swap, disk, load, uptime), Network (each interface's rates and
totals), Stacks (each container's state, health and memory), Traffic (the gate's requests and the
domains), Certificates (the certificate service in use and the hosts it issues for), Ports (the
listening sockets) and Activity (the newest audit entries). Each widget reads its verb again every
five seconds while it is shown. A read that fails is one line in the widget, which keeps what it
last showed.

**Why tiles:** an administrator opens the panel to see how the host is doing, so that is the
first screen. A tile manager gives every widget a place without overlap, and the user moves and
resizes them with Alt-drags. A table of facts about the panel itself told the user little.

**Why a failed read stays in the widget:** the screen reads every few seconds. A dialog for each
failure would stop the screen again and again; a line in the widget says it where it applies.

**Why a hidden widget is not read:** it shows nothing, so its verb would cost the daemon for no
one. The status and the routes are read on every tick, for the status bar.

**Where a widget is** is kept for the session: a theme's reload keeps it. The daemon's preferences
hold only the theme and the language.

**What the widgets do not show yet:** the gate counts requests in total, not by domain, and no verb
lists certificates with their expiry. The Traffic widget says so, and the Certificates widget shows
the certificate service and the hosts the routes serve.

**In the code:** `internal/ui/qml/Main.qml` (the `TileManager`), `internal/ui/widgets.go`
(`poll`, `hostGauges`, `networkRows`), `internal/ui/dock.go` (`widgetSpecs`);
`TestEveryWidgetRendersFromTheDaemon`, `TestAFailedReadShowsInTheWidget`, `TestTheScreenIsReadAgain`.

## Panels are golib's Panel

**Decided:** every panel the menus open (the routes, the domains, the System monitors, the
stacks, a stack's log, the terminal) is golib's `Panel` from `tui.panels`. It floats over the
widgets, moves and resizes with Alt-drags, and closes on `q` or Escape. AutoPanel has no panel
component of its own.

**Why:** one look for every panel, the same as AutoDoc's, kept up to date by golib. A panel of
AutoPanel's own drifted from the toolkit's, with its own window controls and its own line of keys.

**In the code:** `internal/ui/qml/Main.qml`, `internal/ui/dock.go` (`panelSpecs`, `openPanel`);
`TestEveryPanelIsAPanel`.

## The dock replaces the taskbar

**Decided:** the menu bar's right corner is the dock, as in AutoDoc: an icon for each widget, then
one for each open panel. A click hides what is shown and shows what is hidden; a hidden one's icon
is dimmed. Hidden is golib's window minimize: a panel keeps what it holds, and a widget gives its
tile to the ones beside it.

**Why:** the taskbar was a row of its own under the screen, listing only what was minimized. The
dock takes no row, lists everything that can be hidden, and is where AutoDoc's users look already.

**In the code:** `internal/ui/qml/Main.qml` (the `MenuBar`'s `Repeater` over `App.dock`),
`internal/ui/dock.go` (`refreshDock`, `goDock`); `TestTheDockHidesAndShowsAPanel`,
`TestTheDockHidesAndShowsAWidget`.

## A list and what acts on it are two panes

**Decided:** a panel or dialog that lists records and acts on them has two panes: the rows on the
left, the selected row whole on the right, the buttons under both. The stacks, the routes, the
domains, the audit log, the login attempts, the open ports and a stack's review are built this
way. In the stacks panel a button acts on the selected row: a container's row acts on that
service, a stack's row on the whole stack.

**Why:** a row of a table has room for a few short columns, and a record has more to say than
that: an image's digest, a finding's whole sentence, an audit entry's detail. The right pane shows
it whole without a dialog, and the left keeps its place.

**Why a stack's row acts on the whole stack:** the list shows each stack and, under it, its
containers. Acting on what is selected needs no second set of keys for the whole stack.

**In the code:** `internal/ui/qml/Main.qml`, `internal/ui/qml/dialogs/ReviewDialog.qml`,
`internal/ui/monitor.go` (`facts`), `internal/ui/services.go` (`stackRows`, `stackDetail`,
`reviewList`); `TestTheStacksPanel`, `TestTheReviewIsTwoPanes`, `TestSystemMonitors`.

## Access keys replace the help lines

**Decided:** no line of the screen lists keys: no hints row, no line of keys under a panel, no
dialog help text. Each button carries its key as an access key in its label (`&Add…`,
`Close (&q)`), drawn in the accent colour, and says what it does in its tooltip. Help › Keys is the
one place every key is listed.

**Why:** a line of keys is read once and then takes a row for good, and it goes stale when a key
changes. A key in its button's label is where the eye already is, and it cannot disagree with the
button.

**Why the keys still work in a panel:** a panel is not a dialog, and golib presses a button by its
access key only in a dialog. Each panel declares the same letters as shortcuts, and a test holds
every button's letter to its panel's shortcuts. None is `h`, `j`, `k` or `l`, which move a list.

**Why tooltips are the host's text:** golib's `toolTipText` takes plain text, not a catalog
message. The host fills each one from the catalog, in the language shown, and fills them again
when the language changes.

**In the code:** `internal/ui/keys.go` (`keySections`, `tips`), the QML's `Button`s;
`TestNoHelpLineOnAnyScreen`, `TestNoHelpTextInTheSource`, `TestEveryButtonHasAnAccessKeyAndATooltip`,
`TestAButtonsKeyIsItsPanelsKey`, `TestNoPanelKeyMovesAList`.

## A stack is added from a file browser

**Decided:** Services › Add a stack opens a file browser in the pickers' layout: a path field over
the folder's entries on the left, folders first and a folder that holds a `compose.yaml` marked;
the entry under the cursor on the right. Enter goes into a folder, Backspace goes up. Import takes
a folder that holds a `compose.yaml`, asks the stack's name (the folder's own first), copies the
definition in and opens its review. It starts in the home of the user who ran `sudo`.

**Why:** a stack can be imported from any folder (see
[services](services.md#a-stack-is-imported-from-anywhere)), so the screen has to let the user find
it. A preview beside the list shows what is in a file before it is imported.

**What the preview shows:** only a file inside a stack's folder, with every value of a `.env` and
each secret's value masked; the daemon decides both. For any other file a one-line note says why
nothing is shown. A note never stands in for an error: a folder that cannot be read is said as one.

**In the code:** `internal/ui/browse.go`, `internal/ui/qml/dialogs/BrowseDialog.qml`;
`TestTheFileBrowser`, `TestImportFromTheBrowser`.

## A route's host is a subdomain and a domain

**Decided:** the route form asks for the host in two parts: a subdomain, typed, and a domain,
chosen from the registered ones. The host stored is `subdomain.domain`, or the domain alone. The
upstream is typed, or filled from a port a stack publishes, offered as `http://127.0.0.1:<port>`
under its stack's and service's names.

**Why:** a route's host is under a registered domain (see [routes](routes.md)). Choosing the
domain makes a host under none hard to type by mistake, and the daemon still refuses one.

**In the code:** `internal/ui/routes.go` (`formHost`, `splitHost`, `stackPorts`),
`internal/ui/qml/dialogs/RouteDialog.qml`; `TestTheRouteFormsDomainAndPort`, `TestSplitHost`.
