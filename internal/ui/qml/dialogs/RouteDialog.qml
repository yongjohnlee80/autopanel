// RouteDialog.qml — the form that adds a route or edits one.
//
// The host fills App.formTitle and the three fields' sources, then opens it.
// OK is an ActionRole button: it runs App.submit and the dialog stays, so a
// change the daemon refuses leaves the form as typed, with the reason in the
// help line (App.formHelp). The host closes the dialog once the change is
// made. Enter in any field submits too; Escape and Cancel close it unchanged.

Dialog {
    title: App.formTitle
    helpText: App.formHelp
    width: 64

    Flex {
        direction: Tui.Vertical
        Text { text: "Host" }
        TextField {
            id: hostField
            text: App.formHost
            placeholderText: "example.com"
            onAccepted: App.submit(hostField.text, pathField.text, upstreamField.text)
        }
        Text { text: "Path prefix" }
        TextField {
            id: pathField
            text: App.formPath
            placeholderText: "/"
            onAccepted: App.submit(hostField.text, pathField.text, upstreamField.text)
        }
        Text { text: "Upstream URL" }
        TextField {
            id: upstreamField
            text: App.formUpstream
            placeholderText: "http://127.0.0.1:8080"
            onAccepted: App.submit(hostField.text, pathField.text, upstreamField.text)
        }
    }

    DialogButtonBox {
        Button {
            text: "&OK"
            DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
            onClicked: App.submit(hostField.text, pathField.text, upstreamField.text)
        }
        Button {
            text: "&Cancel"
            DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
        }
    }
}
