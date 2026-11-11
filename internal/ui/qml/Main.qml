// Main.qml — AutoPanel's admin screen.
//
// Structure only: what is on screen and what each key or control triggers.
// The Go host (package ui) owns the behaviour: it keeps the routes model and
// the status values (App.*), and runs the commands (App.add() and the rest)
// through the daemon's client, reading the routes again after each change.

import tui 1.0                 // the widget vocabulary, and the Tui singleton's enums
import autopanel 1.0           // the App singleton: the panel's state and commands
import autopanel.dialogs 1.0   // RouteDialog, ConfirmDialog

Window {
    // ---- keys -------------------------------------------------------------
    //
    // The Window sees every key the focused widget leaves; the routes table
    // leaves these letters, so they work while it has the keyboard. Each
    // passes the row under the cursor; the host checks it is a route.
    Shortcut { sequence: "a"; onActivated: App.add() }
    Shortcut { sequence: "e"; onActivated: App.edit(routes.currentIndex) }
    Shortcut { sequence: "d"; onActivated: App.remove(routes.currentIndex) }
    Shortcut { sequence: "r"; onActivated: App.refresh() }
    Shortcut { sequence: "q"; onActivated: App.quit() }
    Shortcut { sequence: "Ctrl+C"; onActivated: App.quit() }

    // ---- the title --------------------------------------------------------
    Text {
        Dock.edge: Tui.Top
        text: " AutoPanel"
        font.bold: true
    }

    // ---- the routes -------------------------------------------------------
    //
    // No Dock.edge, so it fills what the bars leave. Enter on a row edits it.
    Frame {
        title: "Routes"
        TableView {
            id: routes
            focus: true
            model: App.routes
            onActivated: App.edit(index)
            TableViewColumn { role: "id"; title: "ID"; width: 6 }
            TableViewColumn { role: "host"; title: "Host" }
            TableViewColumn { role: "path"; title: "Path" }
            TableViewColumn { role: "upstream"; title: "Upstream" }
        }
    }

    // ---- the bars, bottom up: the key hints, then the status --------------
    StatusBar {
        Dock.edge: Tui.Bottom
        left: "a add · e/Enter edit · d delete · r refresh · q quit"
    }
    StatusBar {
        Dock.edge: Tui.Bottom
        left: App.status
        right: App.message
    }

    // ---- dialogs ----------------------------------------------------------
    //
    // The host fills a dialog's sources, then opens it by id; each closes
    // itself on Cancel, No or Escape. The route form stays open on a failed
    // change, showing why; the host closes it once the change is made.
    RouteDialog { id: routeDialog }
    ConfirmDialog { id: confirmDialog }
}
