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
import autopanel.dialogs 1.0   // Login, RouteDialog, ConfirmDialog
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
            MenuItem { text: qsTrId("autopanel.menu.services.turn"); enabled: false }
            MenuItem { text: qsTrId("autopanel.menu.services.mail"); enabled: false }
        }
        Menu {
            title: qsTrId("autopanel.menu.users")
            MenuItem { text: qsTrId("autopanel.menu.users.manage"); enabled: false }
        }
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
                TableViewColumn { role: "user"; title: "USER"; width: 14 }
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
        size: 65; length: 80
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
                TableViewColumn { role: "address"; title: "LISTENS ON"; width: 26 }
                TableViewColumn { role: "use"; title: "FOR" }
            }
            Text { text: App.portsNote }
            Text { text: qsTrId("autopanel.monitor.help") }
        }
    }

    // ---- dialogs ----------------------------------------------------------
    //
    // The host fills a dialog's sources, then opens it by id; each closes
    // itself on Close, Cancel, No or Escape. The route form stays open on a
    // failed change, showing why; the host closes it once the change is made.
    Login { id: loginDialog }
    RouteDialog { id: routeDialog }
    ConfirmDialog { id: confirmDialog }
    About { id: aboutDialog }
}
