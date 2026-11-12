// Main.qml — AutoPanel's admin screen.
//
// Structure only: the menu bar, the overview, the two bars, the floating
// panels, and what each menu row or key triggers. It names no colour (the
// imported theme does) and no text (the catalogs do), and runs nothing
// itself. The Go host (package ui) owns the behaviour: it keeps the models
// and the status values (App.*), and runs the commands through the daemon's
// client, reading the routes and the status again after each change.
//
// A menu row that is not built yet is declared disabled, so the menu shows
// where each part of the panel will live.

import tui 1.0                 // the widget vocabulary, and the Tui singleton's enums
import autopanel 1.0           // the App singleton: the panel's state and commands
import autopanel.theme.dark 1.0  // the Theme singleton; System › Theme switches it
import autopanel.dialogs 1.0   // Login, RouteDialog, TurnDialog, ConfirmDialog
import autopanel.views 1.0     // About
import autopanel.panels 1.0    // FloatPanel

Window {
    palette.window: Theme.app.window
    palette.windowText: Theme.app.windowText
    palette.button: Theme.app.button
    palette.buttonText: Theme.app.buttonText
    palette.highlight: Theme.app.highlight
    palette.accent: Theme.menu.accent    // the access keys' colour
    palette.highlightedText: Theme.app.highlightedText
    palette.base: Theme.app.base
    palette.text: Theme.app.text
    palette.inactive.highlight: Theme.app.inactive.highlight
    palette.inactive.highlightedText: Theme.app.inactive.highlightedText
    palette.mid: Theme.app.mid
    palette.light: Theme.app.light

    // ---- keys -------------------------------------------------------------
    //
    // The Window sees every key the focused widget leaves. The rest of the
    // panel is reached through the menu bar: Alt and a menu's letter, or F10.
    Shortcut { sequence: "r"; onActivated: App.refresh() }
    Shortcut { sequence: "q"; onActivated: App.quit() }
    Shortcut { sequence: "Ctrl+C"; onActivated: App.quit() }

    // ---- the menu bar -----------------------------------------------------
    MenuBar {
        Dock.edge: Tui.Top
        vimNavigation: true
        palette.window: Theme.menu.window
        palette.windowText: Theme.menu.windowText
        palette.highlight: Theme.menu.highlight
        palette.highlightedText: Theme.menu.highlightedText
        palette.accent: Theme.menu.accent

        Menu {
            title: qsTrId("autopanel.menu.system")
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
            title: qsTrId("autopanel.menu.routes")
            MenuItem { text: qsTrId("autopanel.menu.routes.proxy"); onTriggered: App.openRoutes() }
            MenuItem { text: qsTrId("autopanel.menu.routes.forwarding"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.certs")
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
            title: qsTrId("autopanel.menu.services")
            MenuItem { text: qsTrId("autopanel.menu.services.deployed"); onTriggered: App.openServices() }
            MenuItem { text: qsTrId("autopanel.menu.services.turn"); onTriggered: App.deployTurn() }
            MenuItem { text: qsTrId("autopanel.menu.services.mail"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.users")
            MenuItem { text: qsTrId("autopanel.menu.users.manage"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.go")
            // checked while the panel is open; its shells run on while it is hidden
            MenuItem { text: qsTrId("autopanel.menu.go.terminal"); checkable: true; checked: App.terminalShown; onTriggered: App.toggleTerminal() }
        }
        Menu {
            title: qsTrId("autopanel.menu.help")
            MenuItem { text: qsTrId("autopanel.menu.help.about"); onTriggered: aboutDialog.open() }
        }
    }

    // ---- the overview -----------------------------------------------------
    //
    // The running AutoPanel, a fact per row. No Dock.edge, so it fills what
    // the bars leave. It is the Window's focus target: the keyboard comes
    // back to it after a menu action or a dialog, so the Window's keys work.
    Frame {
        title: qsTrId("autopanel.overview.title")
        TableView {
            id: overview
            focus: true
            palette.highlight: Theme.document.highlight
            palette.highlightedText: Theme.document.highlightedText
            model: App.overview
            TableViewColumn { role: "name"; title: "ITEM"; width: 16 }
            TableViewColumn { role: "value"; title: "VALUE" }
        }
    }

    // ---- the bars, bottom up: the status, then the hints ------------------
    //
    // The status bar's left is the running AutoPanel in one line; its right
    // is what the last command did. Above it, the key hints, and the panels
    // that are minimized: a press on one brings its panel back.
    StatusBar {
        Dock.edge: Tui.Bottom
        palette.window: Theme.status.window
        palette.windowText: Theme.status.windowText
        left: App.status
        right: App.message
    }
    Flex {
        Dock.edge: Tui.Bottom
        direction: Tui.Horizontal
        Text { text: qsTrId("autopanel.hints"); Layout.fillWidth: true }
        WindowTaskbar {}
    }

    // ---- the floating panels ----------------------------------------------
    //
    // Each opens from its menu row, in the middle, and stays until closed.
    // The keys declared in a panel are live while the keyboard is in it.
    FloatPanel {
        id: routesPanel
        key: "routes"; label: "Proxy routes"
        heading: qsTrId("autopanel.routes.title")
        onOpened: routesTable.forceActiveFocus()
        Shortcut { sequence: "a"; onActivated: App.add() }
        Shortcut { sequence: "e"; onActivated: App.edit(routesTable.currentIndex) }
        Shortcut { sequence: "d"; onActivated: App.remove(routesTable.currentIndex) }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: routesTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.routes
                onActivated: App.edit(index)
                TableViewColumn { role: "id"; title: "ID"; width: 6 }
                TableViewColumn { role: "host"; title: "HOST" }
                TableViewColumn { role: "path"; title: "PATH" }
                TableViewColumn { role: "upstream"; title: "UPSTREAM" }
            }
            Flex {
                direction: Tui.Horizontal
                Button { text: qsTrId("autopanel.routes.add"); onClicked: App.add() }
                Button { text: qsTrId("autopanel.routes.edit"); onClicked: App.edit(routesTable.currentIndex) }
                Button { text: qsTrId("autopanel.routes.delete"); onClicked: App.remove(routesTable.currentIndex) }
            }
            Text { text: qsTrId("autopanel.routes.help") }
        }
    }
    FloatPanel {
        id: metricsPanel
        key: "metrics"; label: "Metrics"
        heading: qsTrId("autopanel.metrics.title")
        size: 55; length: 70
        onOpened: metricsTable.forceActiveFocus()
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("metrics") }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: metricsTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.metrics
                TableViewColumn { role: "name"; title: "ITEM"; width: 26 }
                TableViewColumn { role: "value"; title: "VALUE" }
            }
            Text { text: App.metricsNote }
            Text { text: qsTrId("autopanel.monitor.help") }
        }
    }
    FloatPanel {
        id: auditPanel
        key: "audit"; label: "Audit log"
        heading: qsTrId("autopanel.audit.title")
        size: 75; length: 90
        onOpened: auditTable.forceActiveFocus()
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("audit") }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: auditTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.audit
                TableViewColumn { role: "time"; title: "TIME"; width: 20 }
                TableViewColumn { role: "actor"; title: "WHO"; width: 20 }
                TableViewColumn { role: "action"; title: "ACTION"; width: 16 }
                TableViewColumn { role: "subject"; title: "SUBJECT" }
                TableViewColumn { role: "detail"; title: "DETAIL" }
            }
            Text { text: App.auditNote }
            Text { text: qsTrId("autopanel.monitor.help") }
        }
    }
    FloatPanel {
        id: loginsPanel
        key: "logins"; label: "Login attempts"
        heading: qsTrId("autopanel.logins.title")
        size: 75; length: 90
        onOpened: loginsTable.forceActiveFocus()
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("logins") }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: loginsTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.logins
                TableViewColumn { role: "time"; title: "TIME"; width: 20 }
                TableViewColumn { role: "source"; title: "TO"; width: 6 }
                TableViewColumn { role: "user"; title: "USER"; width: 12 }
                TableViewColumn { role: "from"; title: "FROM"; width: 24 }
                TableViewColumn { role: "result"; title: "RESULT"; width: 10 }
                TableViewColumn { role: "detail"; title: "DETAIL" }
            }
            Text { text: App.loginsNote; wrapMode: Tui.WordWrap }
            Text { text: qsTrId("autopanel.monitor.help") }
        }
    }
    FloatPanel {
        id: portsPanel
        key: "ports"; label: "Open ports"
        heading: qsTrId("autopanel.ports.title")
        size: 65; length: 90
        onOpened: portsTable.forceActiveFocus()
        Shortcut { sequence: "r"; onActivated: App.reloadMonitor("ports") }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: portsTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.ports
                TableViewColumn { role: "proto"; title: "PROTOCOL"; width: 9 }
                TableViewColumn { role: "port"; title: "PORT"; width: 7 }
                TableViewColumn { role: "address"; title: "LISTENS ON"; width: 18 }
                TableViewColumn { role: "process"; title: "PROCESS"; width: 20 }
                TableViewColumn { role: "user"; title: "USER"; width: 11 }
                TableViewColumn { role: "use"; title: "FOR" }
            }
            Text { text: App.portsNote }
            Text { text: qsTrId("autopanel.monitor.help") }
        }
    }

    // ---- the services -----------------------------------------------------
    //
    // Services › Deployed services: a row per service, and its keys
    // (services.go). None is h, j, k or l: the table moves by them. The daemon records each change before it makes it.
    FloatPanel {
        id: servicesPanel
        key: "services"; label: "Services"
        heading: qsTrId("autopanel.services.title")
        size: 70; length: 90
        onOpened: servicesTable.forceActiveFocus()
        onClosed: App.servicesClosed()   // its log and secrets hand the keyboard back to it while it is open
        Shortcut { sequence: "r"; onActivated: App.reloadServices() }
        Shortcut { sequence: "a"; onActivated: App.deployTurn() }
        Shortcut { sequence: "e"; onActivated: App.editService(servicesTable.currentIndex) }
        Shortcut { sequence: "s"; onActivated: App.startService(servicesTable.currentIndex) }
        Shortcut { sequence: "x"; onActivated: App.stopService(servicesTable.currentIndex) }
        Shortcut { sequence: "t"; onActivated: App.restartService(servicesTable.currentIndex) }
        Shortcut { sequence: "o"; onActivated: App.serviceLogsOf(servicesTable.currentIndex) }
        Shortcut { sequence: "c"; onActivated: App.secretsOf(servicesTable.currentIndex) }
        Shortcut { sequence: "d"; onActivated: App.removeService(servicesTable.currentIndex) }
        Shortcut { sequence: "Shift+D"; onActivated: App.purgeService(servicesTable.currentIndex) }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: servicesTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.services
                onActivated: App.editService(index)
                TableViewColumn { role: "name"; title: "NAME"; width: 14 }
                TableViewColumn { role: "kind"; title: "KIND"; width: 12 }
                TableViewColumn { role: "state"; title: "STATE"; width: 20 }
                TableViewColumn { role: "memory"; title: "MEMORY"; width: 10 }
                TableViewColumn { role: "user"; title: "USER"; width: 12 }
                TableViewColumn { role: "ports"; title: "PORTS" }
            }
            Flex {
                direction: Tui.Horizontal
                Button { text: qsTrId("autopanel.services.deploy"); onClicked: App.deployTurn() }
                Button { text: qsTrId("autopanel.services.change"); onClicked: App.editService(servicesTable.currentIndex) }
                Button { text: qsTrId("autopanel.services.start"); onClicked: App.startService(servicesTable.currentIndex) }
                Button { text: qsTrId("autopanel.services.stop"); onClicked: App.stopService(servicesTable.currentIndex) }
                Button { text: qsTrId("autopanel.services.restart"); onClicked: App.restartService(servicesTable.currentIndex) }
                Button { text: qsTrId("autopanel.services.logs"); onClicked: App.serviceLogsOf(servicesTable.currentIndex) }
                Button { text: qsTrId("autopanel.services.remove"); onClicked: App.removeService(servicesTable.currentIndex) }
            }
            Text { text: App.servicesNote }
            Text { text: qsTrId("autopanel.services.help"); wrapMode: Tui.WordWrap }
        }
    }
    FloatPanel {
        id: serviceLogsPanel
        key: "serviceLogs"; label: "Service log"
        heading: qsTrId("autopanel.services.logs.title")
        size: 75; length: 95
        onOpened: serviceLogsTable.forceActiveFocus()
        Shortcut { sequence: "r"; onActivated: App.reloadLogs() }
        Flex {
            direction: Tui.Vertical
            TableView {
                id: serviceLogsTable
                Layout.fillHeight: true
                palette.highlight: Theme.document.highlight
                palette.highlightedText: Theme.document.highlightedText
                model: App.serviceLogs
                TableViewColumn { role: "line"; title: "JOURNAL" }
            }
            Text { text: App.serviceLogsNote }
            Text { text: qsTrId("autopanel.monitor.help") }
        }
    }
    // A service's secrets. Its own Drawer, not a FloatPanel: closing it has
    // the host forget what it showed (App.secretsClosed).
    Drawer {
        id: serviceSecretsPanel
        key: "serviceSecrets"; label: "Secrets"
        modal: false
        closeOnQ: true
        edge: Tui.Center
        size: 30
        length: 90
        movable: true
        windowResize: true
        closable: true
        onOpened: serviceSecretsTable.forceActiveFocus()
        onClosed: App.secretsClosed()
        Frame {
            title: App.secretsTitle
            palette.window: Theme.document.base
            Flex {
                direction: Tui.Vertical
                WindowButtons {}
                FocusScope {
                    Layout.fillHeight: true
                    Shortcut { sequence: "r"; onActivated: App.nothing() }
                    Flex {
                        direction: Tui.Vertical
                        TableView {
                            id: serviceSecretsTable
                            Layout.fillHeight: true
                            palette.highlight: Theme.document.highlight
                            palette.highlightedText: Theme.document.highlightedText
                            model: App.serviceSecrets
                            TableViewColumn { role: "name"; title: "SECRET"; width: 16 }
                            TableViewColumn { role: "value"; title: "VALUE" }
                        }
                        Text { text: qsTrId("autopanel.services.secret.note"); wrapMode: Tui.WordWrap }
                    }
                }
            }
        }
    }

    // ---- the terminal -----------------------------------------------------
    //
    // Go › Terminal: shells on this host, a tab each (terminal.go). The strip
    // is the view's own: a tab per shell, + for another, ≡ for the tab's menu,
    // and the window controls: _ minimizes the panel, its shells kept; the
    // box maximizes it; x stops every shell and closes it.
    //
    // While a shell has the keyboard every key is its program's, but the ones
    // hostKeys names. Ctrl+T leaves the program for the scrollback: move,
    // select and copy as in vim, i to go back. There, q and Esc hide the panel
    // (its shells run on), and the keys shadowed below stay out of the
    // Window's: Ctrl+C would quit the panel, and its shells with it.
    Drawer {
        id: terminalPanel
        key: "terminal"; label: "Terminal"
        modal: false
        closeOnQ: true
        edge: Tui.Center
        size: 80
        length: 90
        movable: true
        windowResize: true
        maximizable: true
        minimizable: true
        closable: true
        onOpened: App.terminalOpened()
        onClosed: App.terminalClosed()
        onChanged: App.panelChanged(operation)
        Frame {
            title: qsTrId("autopanel.terminal.title")
            palette.window: Theme.document.base
            Flex {
                direction: Tui.Vertical
                FocusScope {
                    Layout.fillHeight: true
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
                Text { text: qsTrId("autopanel.terminal.help") }
            }
        }
    }

    // ---- dialogs ----------------------------------------------------------
    //
    // The host fills a dialog's sources, then opens it by id; each closes
    // itself on Close, Cancel, No or Escape. The route form stays open on a
    // failed change, showing why; the host closes it once the change is made.
    Login { id: loginDialog }
    RouteDialog { id: routeDialog }
    TurnDialog { id: turnDialog }
    ConfirmDialog { id: confirmDialog }
    About { id: aboutDialog }
}
