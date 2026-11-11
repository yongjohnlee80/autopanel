// FloatPanel.qml — a floating panel: a window over the screen, framed under
// its heading, with the three window controls in its top row (minimize,
// maximize, close). It opens in the middle; Alt (Option) with the left button
// drags it, Alt with the right button resizes it. Esc and q close it.
//
// It is non-modal, so the menu bar and the other panels stay live under it.
// A use gives its id, its window key and label, its heading, and its content:
// one view, with the Shortcuts that are live while the keyboard is in the
// panel. Both go into the FocusScope, so the panel's keys win there over the
// Window's.
//
// A panel that closes or minimizes hands the keyboard back to the main
// screen (App.panelLeft): it is non-modal, so nothing else would, and the
// keyboard would stay on the menu bar its row was chosen from.
Drawer {
    property var heading: ""                      // a string, or a qsTrId message
    default property alias content: scope.data
    modal: false
    closeOnQ: true
    edge: Tui.Center
    size: 70
    length: 80
    movable: true
    windowResize: true
    maximizable: true
    minimizable: true
    closable: true
    onClosed: App.panelLeft()
    onChanged: App.panelChanged(operation)
    Frame {
        title: heading
        palette.window: Theme.document.base
        Flex {
            direction: Tui.Vertical
            WindowButtons {}
            FocusScope { id: scope; Layout.fillHeight: true }
        }
    }
}
