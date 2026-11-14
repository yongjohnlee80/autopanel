// ConfirmDialog.qml — the one yes-or-no question asked before what a key
// cannot undo: a route or a domain removed, a stack stopped or removed, the
// terminal's running shells stopped.
//
// The host sets App.confirmTitle and App.confirmQuestion, then opens it. No
// comes first, so Enter alone answers No; n and y answer by their access
// keys, and Escape leaves it. A third button, when the question has one,
// answers otherwise (a stack removed with its directory).

Dialog {
    title: App.confirmTitle
    width: 64
    maxWidthPercent: 90
    onAccepted: App.confirmed()
    Text { text: App.confirmQuestion; wrapMode: Tui.WordWrap }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.confirm.no"); toolTipText: App.tipConfirmNo; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
        Button { text: App.confirmOther; toolTipText: App.tipConfirmOther; visible: App.confirmHasOther; enabled: App.confirmHasOther
                 DialogButtonBox.buttonRole: DialogButtonBox.DestructiveRole; onClicked: App.confirmedOther() }
        Button { text: qsTrId("autopanel.button.confirm.yes"); toolTipText: App.tipConfirmYes; DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole }
    }
}
