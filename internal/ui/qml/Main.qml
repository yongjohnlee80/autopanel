// Main.qml — AutoPanel's admin screen.
//
// Structure only: the menu bar, the overview, the two bars, and what each
// menu row or key triggers. The Go host (package ui) owns the behaviour: it
// keeps the routes model and the status values (App.*), and runs the commands
// (App.openRoutes() and the rest) through the daemon's client, reading the
// routes and the status again after each change.
//
// A menu row that is not built yet is declared disabled, so the menu shows
// where each part of the panel will live.

import tui 1.0                 // the widget vocabulary, and the Tui singleton's enums
import autopanel 1.0           // the App singleton: the panel's state and commands
import autopanel.dialogs 1.0   // RoutesManager, RouteDialog, ConfirmDialog
import autopanel.views 1.0     // About

Window {
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

        Menu {
            title: "&Routes"
            MenuItem { text: "&Proxy routes…"; onTriggered: App.openRoutes() }
            MenuItem { text: "Port &forwarding…"; enabled: false }
        }
        Menu {
            title: "&Certs"
            // Which Let's Encrypt service issues the certificates. A shared
            // group makes the two a radio set; the host checks the one in use.
            Menu {
                title: "&Type"
                MenuItem { text: "&Production (trusted certificates)"; group: "ca"; checked: App.caProduction; onTriggered: App.setCA("production") }
                MenuItem { text: "&Staging (test certificates)";       group: "ca"; checked: App.caStaging;    onTriggered: App.setCA("staging") }
            }
            MenuItem { text: "&Cloudflare token…"; enabled: false }
        }
        Menu {
            title: "&Services"
            MenuItem { text: "&TURN server…"; enabled: false }
            MenuItem { text: "&Mail server…"; enabled: false }
        }
        Menu {
            title: "&Users"
            MenuItem { text: "&Manage users…"; enabled: false }
        }
        Menu {
            title: "S&ystem"
            MenuItem { text: "&Refresh (r)"; onTriggered: App.refresh() }
            MenuSeparator {}
            MenuItem { text: "&Audit log…"; enabled: false }
            MenuItem { text: "&Login attempts…"; enabled: false }
            MenuItem { text: "Open &ports…"; enabled: false }
            MenuSeparator {}
            MenuItem { text: "&Quit (q)"; onTriggered: App.quit() }
        }
        Menu {
            title: "&Help"
            MenuItem { text: "&About AutoPanel"; onTriggered: aboutDialog.open() }
        }
    }

    // ---- the overview -----------------------------------------------------
    //
    // The running AutoPanel, a fact per row. No Dock.edge, so it fills what
    // the bars leave. It is the Window's focus target: the keyboard comes
    // back to it after a menu action or a dialog, so the Window's keys work.
    Frame {
        title: "Overview"
        TableView {
            id: overview
            focus: true
            model: App.overview
            TableViewColumn { role: "name"; title: "Item"; width: 16 }
            TableViewColumn { role: "value"; title: "Value" }
        }
    }

    // ---- the bars, bottom up: the status, then the key hints --------------
    //
    // The status bar's left is the running AutoPanel in one line; its right
    // is what the last command did.
    StatusBar {
        Dock.edge: Tui.Bottom
        left: App.status
        right: App.message
    }
    StatusBar {
        Dock.edge: Tui.Bottom
        left: "Menus: Alt and a menu's letter, or F10 · r refresh · q quit"
    }

    // ---- dialogs ----------------------------------------------------------
    //
    // The host fills a dialog's sources, then opens it by id; each closes
    // itself on Close, Cancel, No or Escape. The route form stays open on a
    // failed change, showing why; the host closes it once the change is made.
    RoutesManager { id: routesManager }
    RouteDialog { id: routeDialog }
    ConfirmDialog { id: confirmDialog }
    About { id: aboutDialog }
}
