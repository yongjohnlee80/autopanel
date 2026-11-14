// Login.qml — sign in: a panel user, the passphrase, and the two-factor code
// (left empty without two-factor; it is always sent, H1). While the vault is
// locked it says so before anyone types (N3).
//
// It opens as the panel starts, before anything is read. Enter in the code
// field, or Sign in, answers it; Enter in the user field moves to the
// passphrase, and Enter in the passphrase to the code. The host closes it while it asks the daemon, and opens it again
// on a refusal, the reason in a line under the fields (App.loginError). The
// user field keeps the name last tried; the passphrase starts empty each time,
// and has the keyboard. Quit and Escape quit the panel: signed out, it has
// nothing to show.

Dialog {
    title: qsTrId("autopanel.title.dialog.login")
    width: 64
    maxWidthPercent: 90
    dim: true
    Flex {
        direction: Tui.Vertical
        Text { text: qsTrId("autopanel.label.login.user") }
        TextField { id: user; text: App.lastUser; onAccepted: passphrase.forceActiveFocus() }
        Text { text: qsTrId("autopanel.note.login.vaultLocked"); visible: App.loginVaultLocked; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
        Text { text: qsTrId("autopanel.label.login.passphrase") }
        TextField { id: passphrase; echoMode: TextInput.Password; onAccepted: code.forceActiveFocus() }
        Text { text: qsTrId("autopanel.label.login.code") }
        TextField { id: code; onAccepted: App.login(user.text, passphrase.text, code.text) }
        Text { text: App.loginError; visible: App.loginErrorShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.login.signIn"); toolTipText: App.tipLoginSignIn; DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole }
        Button { text: qsTrId("autopanel.button.login.quit"); toolTipText: App.tipLoginQuit; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onOpened: { passphrase.clear(); code.clear(); passphrase.forceActiveFocus() }
    onAccepted: App.login(user.text, passphrase.text, code.text)
    onRejected: App.loginDeclined()
}
