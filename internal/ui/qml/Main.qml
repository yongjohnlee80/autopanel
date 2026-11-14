// Main.qml — AutoPanel's admin screen, in QML.
//
// STRUCTURE ONLY: what is on the screen, where it is docked, and what each
// control triggers. It names no colour (the imported theme does) and no text
// (the catalogs do), and runs nothing itself: every action is an App command,
// and the Go host (package ui) decides what it does through the daemon's
// client.
//
// The screen, top down: the menu bar, with the dock in its right corner; the
// widgets, tiled over the rest of the window (golib's TileManager), each read
// again every few seconds while it is shown; and the status bar. The menus
// open the panels (golib's tui.panels Panel), which float over the widgets
// until they are closed, or hidden in the dock. A list and what acts on it
// are two panes, the rows on the left and the selected row on the right, the
// buttons under both; each button carries its key in its label. No line of
// the screen lists keys: Help › Keys does.
//
// A menu row that is not built yet is declared disabled, so the menu shows
// where each part of the panel will live.

import tui 1.0
import autopanel 1.0              // App: the panel's state and commands
import autopanel.theme.dark 1.0   // the Theme singleton; System › Theme switches it
import autopanel.dialogs 1.0      // Login, RouteDialog, BrowseDialog, ReviewDialog, PromptDialog, ConfirmDialog
import autopanel.views 1.0        // Keys, About
import tui.panels 1.0             // Panel: the panels the menus open (golib)
import tui.tiles 1.0              // TilePanel: the widgets of the main screen (golib)

Window {
    // below this, the screen asks to be enlarged: a terminal's classic size
    minimumWidth: 80
    minimumHeight: 24
    color: Theme.app.backdrop
    palette.window: Theme.app.window
    palette.windowText: Theme.app.windowText
    palette.button: Theme.app.button
    palette.buttonText: Theme.app.buttonText
    palette.highlight: Theme.app.highlight
    palette.accent: Theme.menu.accent    // the access keys' colour: the menu bar's, and every button's
    palette.highlightedText: Theme.app.highlightedText
    palette.base: Theme.app.base
    palette.text: Theme.app.text
    palette.inactive.highlight: Theme.app.inactive.highlight
    palette.inactive.highlightedText: Theme.app.inactive.highlightedText
    palette.mid: Theme.app.mid
    palette.light: Theme.app.light

    // the previews' colours, set once here and inherited by every highlighter
    syntax.keyword: Theme.syntax.keyword
    syntax.controlFlow: Theme.syntax.controlFlow
    syntax.dataType: Theme.syntax.dataType
    syntax.attribute: Theme.syntax.attribute
    syntax.function: Theme.syntax.function
    syntax.string: Theme.syntax.string
    syntax.specialChar: Theme.syntax.specialChar
    syntax.decVal: Theme.syntax.decVal
    syntax.float: Theme.syntax.float
    syntax.baseN: Theme.syntax.baseN
    syntax.constant: Theme.syntax.constant
    syntax.comment: Theme.syntax.comment
    syntax.alert: Theme.syntax.alert
    syntax.import: Theme.syntax.import
    syntax.operator: Theme.syntax.operator

    // ---- the Window's keys: live wherever the focused control leaves them ----
    Shortcut { sequence: "r"; onActivated: App.refresh() }
    Shortcut { sequence: "q"; onActivated: App.quit() }
    Shortcut { sequence: "Ctrl+C"; onActivated: App.quit() }
    Shortcut { sequence: "F1"; onActivated: App.openKeys() }

    // ---- the menu bar, and the dock in its corner ----
    MenuBar {
        Dock.edge: Tui.Top
        vimNavigation: true
        palette.window: Theme.menu.window
        palette.windowText: Theme.menu.windowText
        palette.highlight: Theme.menu.highlight
        palette.highlightedText: Theme.menu.highlightedText
        palette.accent: Theme.menu.accent

        Menu {
            title: qsTrId("autopanel.menu.system.title")
            MenuItem { text: qsTrId("autopanel.menu.system.metrics"); onTriggered: App.openMonitor("metrics") }
            MenuItem { text: qsTrId("autopanel.menu.system.audit"); onTriggered: App.openMonitor("audit") }
            MenuItem { text: qsTrId("autopanel.menu.system.logins"); onTriggered: App.openMonitor("logins") }
            MenuItem { text: qsTrId("autopanel.menu.system.ports"); onTriggered: App.openMonitor("ports") }
            MenuSeparator {}
            Menu {
                title: qsTrId("autopanel.menu.system.theme")
                // golib's themes, every one it ships (theme.go: themeRows)
                Instantiator {
                    model: App.themes
                    MenuItem { text: model.label; group: "theme"; checked: model.checked; onTriggered: App.useTheme(model.key) }
                }
            }
            Menu {
                title: qsTrId("autopanel.menu.system.language")
                // each in its own script, the same in every language (language.go)
                MenuItem { text: "&1. English";            group: "language"; checked: App.language_en;    onTriggered: App.setLanguage("en") }
                MenuItem { text: "&2. 한국어";             group: "language"; checked: App.language_ko_KR; onTriggered: App.setLanguage("ko_KR") }
                MenuItem { text: "&3. 日本語";             group: "language"; checked: App.language_ja_JP; onTriggered: App.setLanguage("ja_JP") }
                MenuItem { text: "&4. 中文";               group: "language"; checked: App.language_zh_CN; onTriggered: App.setLanguage("zh_CN") }
                MenuItem { text: "&5. Español";            group: "language"; checked: App.language_es;    onTriggered: App.setLanguage("es") }
                MenuItem { text: "&6. Português (Brasil)"; group: "language"; checked: App.language_pt_BR; onTriggered: App.setLanguage("pt_BR") }
            }
            MenuSeparator {}
            MenuItem { text: qsTrId("autopanel.menu.system.refresh"); onTriggered: App.refresh() }
            MenuItem { text: qsTrId("autopanel.menu.system.quit"); onTriggered: App.quit() }
        }
        Menu {
            title: qsTrId("autopanel.menu.routes.title")
            MenuItem { text: qsTrId("autopanel.menu.routes.proxy"); onTriggered: App.openRoutes() }
            MenuItem { text: qsTrId("autopanel.menu.routes.domains"); onTriggered: App.openDomains() }
            MenuItem { text: qsTrId("autopanel.menu.routes.forwarding"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.certs.title")
            // Which Let's Encrypt service issues the certificates. A shared
            // group makes the two a radio set; the host checks the one in use.
            Menu {
                title: qsTrId("autopanel.menu.certs.type")
                MenuItem { text: qsTrId("autopanel.menu.certs.production"); group: "ca"; checked: App.caProduction; onTriggered: App.setCA("production") }
                MenuItem { text: qsTrId("autopanel.menu.certs.staging");    group: "ca"; checked: App.caStaging;    onTriggered: App.setCA("staging") }
            }
            MenuItem { text: qsTrId("autopanel.menu.certs.cloudflare"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.services.title")
            MenuItem { text: qsTrId("autopanel.menu.services.stacks"); onTriggered: App.openStacks() }
            MenuItem { text: qsTrId("autopanel.menu.services.add"); onTriggered: App.addStack() }
        }
        Menu {
            title: qsTrId("autopanel.menu.mail.title")
            MenuItem { text: qsTrId("autopanel.menu.mail.none"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.users.title")
            MenuItem { text: qsTrId("autopanel.menu.users.manage"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.go.title")
            // checked while the panel is open; its shells run on while it is hidden
            MenuItem { text: qsTrId("autopanel.menu.go.terminal"); checkable: true; checked: App.terminalShown; onTriggered: App.toggleTerminal() }
        }
        // the screen's parts: the status bar, each widget, and their layout
        Menu {
            title: qsTrId("autopanel.menu.view.title")
            MenuItem { text: qsTrId("autopanel.menu.view.statusBar"); checkable: true; checked: App.statusShown; onTriggered: App.toggleStatusBar() }
            MenuSeparator {}
            MenuItem { text: qsTrId("autopanel.menu.view.host"); checkable: true; checked: App.hostShown; onTriggered: App.toggleWidget("hostWidget") }
            MenuItem { text: qsTrId("autopanel.menu.view.network"); checkable: true; checked: App.networkShown; onTriggered: App.toggleWidget("networkWidget") }
            MenuItem { text: qsTrId("autopanel.menu.view.stacks"); checkable: true; checked: App.stacksWidgetShown; onTriggered: App.toggleWidget("stacksWidget") }
            MenuItem { text: qsTrId("autopanel.menu.view.traffic"); checkable: true; checked: App.trafficShown; onTriggered: App.toggleWidget("trafficWidget") }
            MenuItem { text: qsTrId("autopanel.menu.view.certs"); checkable: true; checked: App.certsShown; onTriggered: App.toggleWidget("certsWidget") }
            MenuItem { text: qsTrId("autopanel.menu.view.ports"); checkable: true; checked: App.portsShown; onTriggered: App.toggleWidget("portsWidget") }
            MenuItem { text: qsTrId("autopanel.menu.view.activity"); checkable: true; checked: App.activityShown; onTriggered: App.toggleWidget("activityWidget") }
            MenuSeparator {}
            MenuItem { text: qsTrId("autopanel.menu.view.reset"); onTriggered: App.resetLayout() }
        }
        Menu {
            title: qsTrId("autopanel.menu.help.title")
            MenuItem { text: qsTrId("autopanel.menu.help.keys"); onTriggered: App.openKeys() }
            MenuItem { text: qsTrId("autopanel.menu.help.about"); onTriggered: aboutDialog.open() }
        }
        // the dock, the bar's corner: one icon per widget, then one per open
        // panel; a click shows or hides it (dock.go). A hidden one's icon is
        // dimmed. color, golib's: a Button wears no palette role
        Flex {
            direction: Tui.Horizontal
            Repeater {
                model: App.dock
                Button { text: model.icon; flat: true; toolTipText: model.title; onClicked: App.goDock(model.key)
                         color: model.hidden ? Theme.document.lineNumber : Theme.menu.windowText }
            }
        }
    }

    // ---- the widgets: the main screen, tiled. Each tile takes its depth from
    // what the tiles before it leave, at its edge; the last fills the rest.
    // Alt-right drag moves a shared border, Alt-left drag re-docks or swaps a
    // tile; its place is kept for the session (dock.go). ----
    TileManager {
        // the host: four gauges and two lines, in two columns (widgets.go: hostGauges)
        TilePanel {
            id: hostWidget
            heading: qsTrId("autopanel.title.widget.host")
            edge: App.hostEdge; size: App.hostSize
            edges: "left right top bottom center"
            minimumWidth: 30; minimumHeight: 5
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("hostWidget", edge)
            onResized: App.widgetResized("hostWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.hostError; visible: App.hostErrorShown; color: Theme.syntax.alert }
                Flex {
                    direction: Tui.Horizontal
                    Flex {
                        direction: Tui.Vertical
                        Layout.fillWidth: true
                        Flex {
                            direction: Tui.Horizontal
                            Text { text: qsTrId("autopanel.label.host.cpu"); Layout.preferredWidth: 9 }
                            Text { text: App.hostCpuBar; color: App.hostCpuHot ? Theme.syntax.alert : Theme.syntax.string }
                            Text { text: " " }
                            Text { text: App.hostCpuValue; Layout.fillWidth: true }
                        }
                        Flex {
                            direction: Tui.Horizontal
                            Text { text: qsTrId("autopanel.label.host.memory"); Layout.preferredWidth: 9 }
                            Text { text: App.hostMemoryBar; color: App.hostMemoryHot ? Theme.syntax.alert : Theme.syntax.string }
                            Text { text: " " }
                            Text { text: App.hostMemoryValue; Layout.fillWidth: true }
                        }
                        Flex {
                            direction: Tui.Horizontal
                            Text { text: qsTrId("autopanel.label.host.swap"); Layout.preferredWidth: 9 }
                            Text { text: App.hostSwapBar; color: App.hostSwapHot ? Theme.syntax.alert : Theme.syntax.string }
                            Text { text: " " }
                            Text { text: App.hostSwapValue; Layout.fillWidth: true }
                        }
                    }
                    Text { text: "  " }
                    Flex {
                        direction: Tui.Vertical
                        Layout.fillWidth: true
                        Flex {
                            direction: Tui.Horizontal
                            Text { text: qsTrId("autopanel.label.host.disk"); Layout.preferredWidth: 9 }
                            Text { text: App.hostDiskBar; color: App.hostDiskHot ? Theme.syntax.alert : Theme.syntax.string }
                            Text { text: " " }
                            Text { text: App.hostDiskValue; Layout.fillWidth: true }
                        }
                        Flex {
                            direction: Tui.Horizontal
                            Text { text: qsTrId("autopanel.label.host.load"); Layout.preferredWidth: 9 }
                            Text { text: App.hostLoad; Layout.fillWidth: true }
                        }
                        Flex {
                            direction: Tui.Horizontal
                            Text { text: qsTrId("autopanel.label.host.uptime"); Layout.preferredWidth: 9 }
                            Text { text: App.hostUptime; Layout.fillWidth: true }
                        }
                    }
                }
            }
        }

        // the newest audit entries
        TilePanel {
            id: activityWidget
            heading: qsTrId("autopanel.title.widget.activity")
            edge: App.activityEdge; size: App.activitySize
            edges: "left right top bottom center"
            minimumWidth: 30; minimumHeight: 4
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("activityWidget", edge)
            onResized: App.widgetResized("activityWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.activityError; visible: App.activityErrorShown; color: Theme.syntax.alert }
                TableView {
                    id: activityTable
                    Layout.fillHeight: true
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.activity
                    onActivated: App.openMonitor("audit")
                    TableViewColumn { role: "time"; title: "TIME"; width: 12 }
                    TableViewColumn { role: "actor"; title: "WHO"; width: 20 }
                    TableViewColumn { role: "action"; title: "ACTION"; width: 18 }
                    TableViewColumn { role: "subject"; title: "SUBJECT" }
                }
            }
        }

        // each container: state, health and memory; Enter opens the stacks panel on it
        TilePanel {
            id: stacksWidget
            heading: qsTrId("autopanel.title.widget.stacks")
            edge: App.stacksWidgetEdge; size: App.stacksWidgetSize
            edges: "left right top bottom center"
            minimumWidth: 30; minimumHeight: 5
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("stacksWidget", edge)
            onResized: App.widgetResized("stacksWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.stacksWidgetError; visible: App.stacksWidgetErrorShown; color: Theme.syntax.alert }
                TableView {
                    id: stackSummaryTable
                    focus: true
                    Layout.fillHeight: true
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.stackSummary
                    onActivated: App.openStackAt(index)
                    TableViewColumn { role: "name"; title: "CONTAINER"; width: 12 }
                    TableViewColumn { role: "state"; title: "STATE"; width: 16 }
                    TableViewColumn { role: "health"; title: "HEALTH"; width: 8 }
                    TableViewColumn { role: "memory"; title: "MEMORY" }
                }
            }
        }

        // each interface: the rates since the last read, and the totals
        TilePanel {
            id: networkWidget
            heading: qsTrId("autopanel.title.widget.network")
            edge: App.networkEdge; size: App.networkSize
            edges: "left right top bottom center"
            minimumWidth: 30; minimumHeight: 4
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("networkWidget", edge)
            onResized: App.widgetResized("networkWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.networkError; visible: App.networkErrorShown; color: Theme.syntax.alert }
                TableView {
                    id: networkTable
                    Layout.fillHeight: true
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.network
                    TableViewColumn { role: "name"; title: "INTERFACE"; width: 10 }
                    TableViewColumn { role: "rx"; title: "IN/S"; width: 9 }
                    TableViewColumn { role: "tx"; title: "OUT/S"; width: 9 }
                    TableViewColumn { role: "rxTotal"; title: "IN"; width: 9 }
                    TableViewColumn { role: "txTotal"; title: "OUT"; width: 9 }
                    TableViewColumn { role: "errors"; title: "ERRORS" }
                }
            }
        }

        // the gate's requests since it started, and each domain with its routes:
        // the requests are not counted by domain
        TilePanel {
            id: trafficWidget
            heading: qsTrId("autopanel.title.widget.traffic")
            edge: App.trafficEdge; size: App.trafficSize
            edges: "left right top bottom center"
            minimumWidth: 24; minimumHeight: 4
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("trafficWidget", edge)
            onResized: App.widgetResized("trafficWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.trafficError; visible: App.trafficErrorShown; color: Theme.syntax.alert }
                Text { text: App.trafficRequests; wrapMode: Tui.WordWrap }
                TableView {
                    id: trafficTable
                    Layout.fillHeight: true
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.trafficDomains
                    onActivated: App.openDomains()
                    TableViewColumn { role: "name"; title: "DOMAIN"; width: 0 }
                    TableViewColumn { role: "routes"; title: "ROUTES"; width: 7 }
                }
            }
        }

        // the certificate service in use, and the hosts it issues for: the
        // centre, the room the other tiles leave
        TilePanel {
            id: certsWidget
            heading: qsTrId("autopanel.title.widget.certs")
            edge: App.certsEdge; size: App.certsSize
            edges: "left right top bottom center"
            minimumWidth: 24; minimumHeight: 4
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("certsWidget", edge)
            onResized: App.widgetResized("certsWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.certsError; visible: App.certsErrorShown; color: Theme.syntax.alert }
                Text { text: App.certIssuer; wrapMode: Tui.WordWrap }
                Text { text: App.certChallenge }
                TableView {
                    id: certsTable
                    Layout.fillHeight: true
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.certHosts
                    onActivated: App.openRoutes()
                    TableViewColumn { role: "host"; title: "HOST"; width: 16 }
                    TableViewColumn { role: "domain"; title: "DOMAIN"; width: 0 }
                }
            }
        }

        // the listening sockets, short: the System menu's panel has them whole.
        // Declared after the centre: a strip takes its depth in this order
        TilePanel {
            id: portsWidget
            heading: qsTrId("autopanel.title.widget.ports")
            edge: App.portsEdge; size: App.portsSize
            edges: "left right top bottom center"
            minimumWidth: 24; minimumHeight: 4
            onChanged: App.widgetChanged()
            onDocked: App.widgetDocked("portsWidget", edge)
            onResized: App.widgetResized("portsWidget", size)
            Flex {
                direction: Tui.Vertical
                Text { text: App.portsError; visible: App.portsErrorShown; color: Theme.syntax.alert }
                TableView {
                    id: portSummaryTable
                    Layout.fillHeight: true
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.portSummary
                    onActivated: App.openMonitor("ports")
                    TableViewColumn { role: "proto"; title: "PROTO"; width: 6 }
                    TableViewColumn { role: "port"; title: "PORT"; width: 6 }
                    TableViewColumn { role: "process"; title: "PROCESS"; width: 12 }
                    TableViewColumn { role: "use"; title: "FOR" }
                }
            }
        }
    }

    // ---- the status bar: the running AutoPanel on the left, when it was
    // read in the centre, what the last action did on the right. View ›
    // Status bar hides it ----
    StatusBar {
        Dock.edge: Tui.Bottom
        visible: App.statusShown
        palette.window: Theme.status.window
        palette.windowText: Theme.status.windowText
        left: App.status
        center: App.statusCenter
        right: App.message
    }

    // ---- the panels: each a Panel (golib's), opened from its menu row in the
    // middle of the screen, until it is closed (q, Esc, Close) or hidden in
    // the dock. A panel's keys are live while the keyboard is in it, and each
    // is a button's access key. None is h, j, k or l: a list moves by them ----

    // Services › Stacks: each stack and its containers on the left, the
    // selected one on the right; a button acts on that row (services.go)
    Panel {
        id: stacksPanel
        key: "stacks"
        heading: qsTrId("autopanel.title.panel.stacks")
        edge: Tui.Center; size: 90; length: 90
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("stacks")
        onClosed: App.panelClosed("stacks")
        onChanged: App.panelChanged("stacks", operation)
        Shortcut { sequence: "a"; onActivated: App.addStack() }
        Shortcut { sequence: "p"; onActivated: App.applyStack(stacksTable.currentIndex) }
        Shortcut { sequence: "t"; onActivated: App.startService(stacksTable.currentIndex) }
        Shortcut { sequence: "x"; onActivated: App.stopService(stacksTable.currentIndex) }
        Shortcut { sequence: "e"; onActivated: App.restartService(stacksTable.currentIndex) }
        Shortcut { sequence: "o"; onActivated: App.logsOf(stacksTable.currentIndex) }
        Shortcut { sequence: "u"; onActivated: App.pullStack(stacksTable.currentIndex) }
        Shortcut { sequence: "s"; onActivated: App.updateFromSource(stacksTable.currentIndex) }
        Shortcut { sequence: "r"; onActivated: App.removeStack(stacksTable.currentIndex) }
        Flex {
            direction: Tui.Vertical
            Split {
                Layout.fillHeight: true
                orientation: Tui.Horizontal
                ratio: 0.5
                Frame {
                    title: App.stacksTitle
                    TableView {
                        id: stacksTable
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.stacks
                        currentIndex: App.stacksAt
                        onCurrentIndexChanged: App.stackMoved(index)
                        onActivated: App.applyStack(index)
                        TableViewColumn { role: "name"; title: "STACK"; width: 14 }
                        TableViewColumn { role: "state"; title: "STATE"; width: 0 }
                        TableViewColumn { role: "health"; title: "HEALTH"; width: 8 }
                    }
                }
                Frame {
                    title: qsTrId("autopanel.title.pane.details")
                    Text { text: App.stackDetail; wrapMode: Tui.WordWrap }
                }
            }
            Flow {
                spacing: 1
                rowSpacing: 0
                Button { text: qsTrId("autopanel.button.stacks.add"); toolTipText: App.tipStacksAdd; onClicked: App.addStack() }
                Button { text: qsTrId("autopanel.button.stacks.apply"); toolTipText: App.tipStacksApply; onClicked: App.applyStack(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.start"); toolTipText: App.tipStacksStart; onClicked: App.startService(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.stop"); toolTipText: App.tipStacksStop; onClicked: App.stopService(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.restart"); toolTipText: App.tipStacksRestart; onClicked: App.restartService(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.logs"); toolTipText: App.tipStacksLogs; onClicked: App.logsOf(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.pull"); toolTipText: App.tipStacksPull; onClicked: App.pullStack(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.update"); toolTipText: App.tipStacksUpdate; enabled: App.stackCanUpdate; onClicked: App.updateFromSource(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.stacks.remove"); toolTipText: App.tipStacksRemove; onClicked: App.removeStack(stacksTable.currentIndex) }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("stacks") }
            }
        }
    }

    // a stack's journal, or one container's, oldest first
    Panel {
        id: stackLogsPanel
        key: "stackLogs"
        heading: qsTrId("autopanel.title.panel.stackLog")
        edge: Tui.Center; size: 85; length: 90
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("stackLogs")
        onClosed: App.panelClosed("stackLogs")
        onChanged: App.panelChanged("stackLogs", operation)
        Shortcut { sequence: "r"; onActivated: App.reloadLogs() }
        Flex {
            direction: Tui.Vertical
            Frame {
                Layout.fillHeight: true
                title: App.stackLogsTitle
                TableView {
                    id: stackLogsTable
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.stackLogs
                    TableViewColumn { role: "line"; title: "JOURNAL" }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.panel.reload"); toolTipText: App.tipLogsReload; onClicked: App.reloadLogs() }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("stackLogs") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // Routes › Proxy routes: the routes on the left, the selected one and its
    // domain on the right (routes.go)
    Panel {
        id: routesPanel
        key: "routes"
        heading: qsTrId("autopanel.title.panel.routes")
        edge: Tui.Center; size: 85; length: 85
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("routes")
        onClosed: App.panelClosed("routes")
        onChanged: App.panelChanged("routes", operation)
        Shortcut { sequence: "a"; onActivated: App.add() }
        Shortcut { sequence: "e"; onActivated: App.edit(routesTable.currentIndex) }
        Shortcut { sequence: "r"; onActivated: App.remove(routesTable.currentIndex) }
        Shortcut { sequence: "m"; onActivated: App.openDomains() }
        Flex {
            direction: Tui.Vertical
            Split {
                Layout.fillHeight: true
                orientation: Tui.Horizontal
                ratio: 0.5
                Frame {
                    title: App.routesTitle
                    TableView {
                        id: routesTable
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.routes
                        onCurrentIndexChanged: App.routeMoved(index)
                        onActivated: App.edit(index)
                        TableViewColumn { role: "id"; title: "ID"; width: 5 }
                        TableViewColumn { role: "host"; title: "HOST"; width: 0 }
                        TableViewColumn { role: "path"; title: "PATH"; width: 10 }
                    }
                }
                Frame {
                    title: qsTrId("autopanel.title.pane.details")
                    Text { text: App.routeDetail; wrapMode: Tui.WordWrap }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.routes.add"); toolTipText: App.tipRoutesAdd; onClicked: App.add() }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.routes.edit"); toolTipText: App.tipRoutesEdit; onClicked: App.edit(routesTable.currentIndex) }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.routes.remove"); toolTipText: App.tipRoutesRemove; onClicked: App.remove(routesTable.currentIndex) }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.routes.domains"); toolTipText: App.tipRoutesDomains; onClicked: App.openDomains() }
                Text { text: " " }
                Button { id: routesClose; text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("routes") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // Routes › Domains: the domains and their routes' counts on the left, the
    // selected one and the routes under it on the right (routes.go)
    Panel {
        id: domainsPanel
        key: "domains"
        heading: qsTrId("autopanel.title.panel.domains")
        edge: Tui.Center; size: 75; length: 80
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("domains")
        onClosed: App.panelClosed("domains")
        onChanged: App.panelChanged("domains", operation)
        Shortcut { sequence: "a"; onActivated: App.addDomain() }
        Shortcut { sequence: "r"; onActivated: App.removeDomain(domainsTable.currentIndex) }
        Flex {
            direction: Tui.Vertical
            Split {
                Layout.fillHeight: true
                orientation: Tui.Horizontal
                ratio: 0.45
                Frame {
                    title: App.domainsTitle
                    TableView {
                        id: domainsTable
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.domains
                        onCurrentIndexChanged: App.domainMoved(index)
                        TableViewColumn { role: "name"; title: "DOMAIN"; width: 0 }
                        TableViewColumn { role: "routes"; title: "ROUTES"; width: 7 }
                    }
                }
                Frame {
                    title: qsTrId("autopanel.title.pane.details")
                    Text { text: App.domainDetail; wrapMode: Tui.WordWrap }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.domains.add"); toolTipText: App.tipDomainsAdd; onClicked: App.addDomain() }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.domains.remove"); toolTipText: App.tipDomainsRemove; onClicked: App.removeDomain(domainsTable.currentIndex) }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("domains") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // System › Metrics: the core's, the gate's and the host's numbers
    Panel {
        id: metricsPanel
        key: "metrics"
        heading: qsTrId("autopanel.title.panel.metrics")
        edge: Tui.Center; size: 60; length: 70
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("metrics")
        onClosed: App.panelClosed("metrics")
        onChanged: App.panelChanged("metrics", operation)
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("metrics") }
        Flex {
            direction: Tui.Vertical
            Frame {
                Layout.fillHeight: true
                title: App.metricsTitle
                TableView {
                    id: metricsTable
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.metrics
                    TableViewColumn { role: "name"; title: "ITEM"; width: 22 }
                    TableViewColumn { role: "value"; title: "VALUE" }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.panel.reload"); toolTipText: App.tipMonitorReload; onClicked: App.reloadMonitor("metrics") }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("metrics") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // System › Audit log: the entries on the left, the selected one whole on the right
    Panel {
        id: auditPanel
        key: "audit"
        heading: qsTrId("autopanel.title.panel.audit")
        edge: Tui.Center; size: 90; length: 90
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("audit")
        onClosed: App.panelClosed("audit")
        onChanged: App.panelChanged("audit", operation)
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("audit") }
        Flex {
            direction: Tui.Vertical
            Split {
                Layout.fillHeight: true
                orientation: Tui.Horizontal
                ratio: 0.55
                Frame {
                    title: App.auditTitle
                    TableView {
                        id: auditTable
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.audit
                        onCurrentIndexChanged: App.monitorMoved("audit", index)
                        TableViewColumn { role: "time"; title: "TIME"; width: 20 }
                        TableViewColumn { role: "actor"; title: "WHO"; width: 18 }
                        TableViewColumn { role: "action"; title: "ACTION"; width: 0 }
                    }
                }
                Frame {
                    title: qsTrId("autopanel.title.pane.entry")
                    Text { text: App.auditDetail; wrapMode: Tui.WordWrap }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.panel.reload"); toolTipText: App.tipMonitorReload; onClicked: App.reloadMonitor("audit") }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("audit") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // System › Login attempts: to the panel and over SSH, the selected one whole on the right
    Panel {
        id: loginsPanel
        key: "logins"
        heading: qsTrId("autopanel.title.panel.logins")
        edge: Tui.Center; size: 85; length: 90
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("logins")
        onClosed: App.panelClosed("logins")
        onChanged: App.panelChanged("logins", operation)
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("logins") }
        Flex {
            direction: Tui.Vertical
            // why the SSH logins are missing, when the journal could not be read
            Text { text: App.loginsNote; visible: App.loginsNoted; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
            Split {
                Layout.fillHeight: true
                orientation: Tui.Horizontal
                ratio: 0.55
                Frame {
                    title: App.loginsTitle
                    TableView {
                        id: loginsTable
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.logins
                        onCurrentIndexChanged: App.monitorMoved("logins", index)
                        TableViewColumn { role: "time"; title: "TIME"; width: 20 }
                        TableViewColumn { role: "source"; title: "TO"; width: 6 }
                        TableViewColumn { role: "user"; title: "USER"; width: 0 }
                        TableViewColumn { role: "result"; title: "RESULT"; width: 10 }
                    }
                }
                Frame {
                    title: qsTrId("autopanel.title.pane.entry")
                    Text { text: App.loginsDetail; wrapMode: Tui.WordWrap }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.panel.reload"); toolTipText: App.tipMonitorReload; onClicked: App.reloadMonitor("logins") }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("logins") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // System › Open ports: the sockets on the left, the selected one whole on the right
    Panel {
        id: portsPanel
        key: "ports"
        heading: qsTrId("autopanel.title.panel.ports")
        edge: Tui.Center; size: 85; length: 85
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.panelOpened("ports")
        onClosed: App.panelClosed("ports")
        onChanged: App.panelChanged("ports", operation)
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("ports") }
        Flex {
            direction: Tui.Vertical
            Split {
                Layout.fillHeight: true
                orientation: Tui.Horizontal
                ratio: 0.5
                Frame {
                    title: App.portsTitle
                    TableView {
                        id: portsTable
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.ports
                        onCurrentIndexChanged: App.monitorMoved("ports", index)
                        TableViewColumn { role: "proto"; title: "PROTO"; width: 6 }
                        TableViewColumn { role: "port"; title: "PORT"; width: 6 }
                        TableViewColumn { role: "address"; title: "LISTENS ON"; width: 16 }
                        TableViewColumn { role: "process"; title: "PROCESS"; width: 0 }
                    }
                }
                Frame {
                    title: qsTrId("autopanel.title.pane.socket")
                    Text { text: App.portsDetail; wrapMode: Tui.WordWrap }
                }
            }
            Flex {
                direction: Tui.Horizontal
                Text { text: " "; Layout.fillWidth: true }
                Button { text: qsTrId("autopanel.button.panel.reload"); toolTipText: App.tipMonitorReload; onClicked: App.reloadMonitor("ports") }
                Text { text: " " }
                Button { text: qsTrId("autopanel.button.panel.close"); toolTipText: App.tipPanelClose; onClicked: App.closePanel("ports") }
                Text { text: " "; Layout.fillWidth: true }
            }
        }
    }

    // Go › Terminal: shells on this host, a tab each (terminal.go). The strip
    // is the view's own: a tab per shell, + for another, ≡ for the tab's
    // menu, and _ (hide, its shells kept), the box (maximize) and x (stop
    // every shell and close). While a shell has the keyboard every key is its
    // program's but the ones hostKeys names; Ctrl+T leaves it for the
    // scrollback, where q and Esc hide the panel and the keys shadowed here
    // stay out of the Window's: Ctrl+C would quit the panel, and its shells.
    Panel {
        id: terminalPanel
        key: "terminal"
        heading: qsTrId("autopanel.title.panel.terminal")
        edge: Tui.Center; size: 80; length: 90
        closeOnQ: true; maximizable: true; closable: true
        onOpened: App.terminalOpened()
        onClosed: App.terminalClosed()
        onChanged: App.panelChanged("terminal", operation)
        Shortcut { sequence: "F11"; onActivated: terminalPanel.toggleMaximize() }
        Shortcut { sequence: "Ctrl+Tab"; onActivated: App.nextShell() }
        Shortcut { sequence: "Ctrl+Shift+Tab"; onActivated: App.previousShell() }
        Shortcut { sequence: "Ctrl+C"; onActivated: App.nothing() }
        Shortcut { sequence: "r"; onActivated: App.nothing() }
        TerminalTabs {
            id: terminalView
            windowButtons: true
            onAddRequested: App.newShell()
            onMinimizeRequested: terminalPanel.minimize()
            onMaximizeRequested: terminalPanel.toggleMaximize()
            onCloseRequested: App.stopShells()
            hostKeys: "F11, Ctrl+Tab, Ctrl+Shift+Tab"
            modeKey: "Ctrl+T"
            vimKeys: false
            emptyText: App.terminalEmpty   // a string: the host keeps it in the UI's language
            minimumContrast: 4.5
            palette.base: Theme.document.base
            palette.text: Theme.app.text
        }
    }

    // ---- the dialogs: the host fills a dialog's sources, then opens it by
    // id; each closes itself on its Close or Cancel and on Escape. A form
    // stays open on a refused answer, saying why under its fields; the host
    // closes it once the change is made ----
    Login { id: loginDialog }
    RouteDialog { id: routeDialog }
    BrowseDialog { id: browseDialog }
    ReviewDialog { id: reviewDialog }
    PromptDialog { id: promptDialog }
    ConfirmDialog { id: confirmDialog }
    Keys { id: keysDialog }
    About { id: aboutDialog }
}
