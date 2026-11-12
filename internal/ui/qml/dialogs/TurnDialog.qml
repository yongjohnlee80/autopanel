// TurnDialog.qml — the form that deploys a TURN relay or changes one.
//
// The host fills App.turnTitle and the fields' sources, then opens it. A new
// relay's name can be typed (App.turnNew); a deployed one's is fixed, and is
// in the title. OK is an ActionRole button: it runs App.submitTurn and the
// dialog stays, so a deploy the daemon refuses leaves the form as typed, with
// the reason in the help line (App.turnHelp). The host closes the dialog once
// the relay is deployed. Enter in any field submits too; Escape and Cancel
// close it unchanged.

Dialog {
    title: App.turnTitle
    helpText: App.turnHelp
    width: 72
    maxWidthPercent: 90

    Flex {
        direction: Tui.Vertical
        Text { text: qsTrId("autopanel.services.turn.name"); visible: App.turnNew }
        TextField {
            id: nameField
            visible: App.turnNew
            text: App.turnName
            placeholderText: "turn"
            onAccepted: App.submitTurn(nameField.text, realmField.text, portField.text, relayField.text)
        }
        Text { text: qsTrId("autopanel.services.turn.realm") }
        TextField {
            id: realmField
            text: App.turnRealm
            placeholderText: "turn.example.com"
            onAccepted: App.submitTurn(nameField.text, realmField.text, portField.text, relayField.text)
        }
        Text { text: qsTrId("autopanel.services.turn.port") }
        TextField {
            id: portField
            text: App.turnPort
            placeholderText: "3478"
            onAccepted: App.submitTurn(nameField.text, realmField.text, portField.text, relayField.text)
        }
        Text { text: qsTrId("autopanel.services.turn.relayPorts") }
        TextField {
            id: relayField
            text: App.turnRelayPorts
            placeholderText: "49152-49999"
            onAccepted: App.submitTurn(nameField.text, realmField.text, portField.text, relayField.text)
        }
    }

    DialogButtonBox {
        Button {
            text: qsTrId("autopanel.form.ok")
            DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
            onClicked: App.submitTurn(nameField.text, realmField.text, portField.text, relayField.text)
        }
        Button {
            text: qsTrId("autopanel.form.cancel")
            DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
        }
    }
}
