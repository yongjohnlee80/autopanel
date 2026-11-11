// RoutesManager.qml — the proxy routes: requests for a host and path prefix,
// and the upstream each goes to.
//
// Add, Edit and Delete are the dialog's buttons: each runs and the manager
// stays open, with the route form or the confirmation over it. Each passes the
// row under the cursor; the host checks it is a route. Enter on a row edits
// it. Close, q and Escape close the manager. The screen behind stays
// undimmed, so the status bar's message for each change can be read.

Dialog {
    title: "Proxy routes"
    closeOnQ: true
    dim: false
    width: 100
    maxWidthPercent: 90
    maxHeightPercent: 85
    helpText: "a add · e/Enter edit · d delete · q close"

    TableView {
        id: routesTable
        model: App.routes
        onActivated: App.edit(index)
        TableViewColumn { role: "id"; title: "ID"; width: 6 }
        TableViewColumn { role: "host"; title: "Host" }
        TableViewColumn { role: "path"; title: "Path" }
        TableViewColumn { role: "upstream"; title: "Upstream" }
    }

    DialogButtonBox {
        Button { text: "&Add"; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole; onClicked: App.add() }
        Button { text: "&Edit"; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole; onClicked: App.edit(routesTable.currentIndex) }
        Button { text: "&Delete"; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole; onClicked: App.remove(routesTable.currentIndex) }
        Button { text: "&Close"; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
}
