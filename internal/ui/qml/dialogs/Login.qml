// Login.qml — sign in: a panel user and the passphrase.
//
// It opens as the panel starts, before anything is read. Answering closes
// it, as a Qt dialog closes; a refused answer (no user, or the service saying
// no) opens it again with the reason on its help line (App.loginError). The
// user field keeps the name last tried; the passphrase starts empty each
// time, and has the keyboard. Cancel and Escape quit the panel: signed out,
// it has nothing to show.

Dialog {
    title: qsTrId("autopanel.login.title")
    width: 64
    maxWidthPercent: 90
    standardButtons: Dialog.Ok | Dialog.Cancel
    defaultButton: Dialog.Ok          // Enter signs in, from either field
    dim: true
    helpText: App.loginError
    Flex {
        direction: Tui.Vertical
        Text { text: qsTrId("autopanel.login.user") }
        TextField { id: user; text: App.lastUser }
        Text { text: qsTrId("autopanel.login.passphrase") }
        TextField { id: passphrase; echoMode: TextInput.Password }
    }
    onOpened: { passphrase.clear(); passphrase.forceActiveFocus() }
    onAccepted: App.login(user.text, passphrase.text)
    onRejected: App.loginDeclined()
}
