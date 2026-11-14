// RouteDialog.qml — the form that adds a route or edits one.
//
// The host fills App.formTitle, the fields' sources and the two boxes'
// models, then opens it. The host is in two parts: a subdomain, typed, and a
// domain, chosen from the registered ones (a route's host is under one);
// with no subdomain the route is the domain's own. The upstream is typed, or
// chosen from the ports the stacks publish, which fills it.
//
// Save runs App.submit and the dialog stays: a change the daemon refuses
// leaves the form as typed, with the reason in the line under the fields
// (App.formError). The host closes it once the change is made. Enter in a
// field saves too; Escape and Cancel close it unchanged.

Dialog {
    title: App.formTitle
    width: 72
    maxWidthPercent: 92
    Flex {
        direction: Tui.Vertical
        Text { text: qsTrId("autopanel.label.form.host") }
        Flex {
            direction: Tui.Horizontal
            TextField {
                id: subField
                Layout.fillWidth: true
                text: App.formSub
                placeholderText: "www"
                onAccepted: App.submit(subField.text, domainBox.currentIndex, pathField.text, upstreamField.text)
            }
            Text { text: " . " }
            ComboBox { id: domainBox; model: App.formDomains; textRole: "label"; maxWidth: 34; currentIndex: App.formDomainIndex
                       toolTipText: App.tipFormDomain }
        }
        Text { text: qsTrId("autopanel.label.form.path") }
        TextField {
            id: pathField
            text: App.formPath
            placeholderText: "/"
            onAccepted: App.submit(subField.text, domainBox.currentIndex, pathField.text, upstreamField.text)
        }
        Text { text: qsTrId("autopanel.label.form.upstream") }
        TextField {
            id: upstreamField
            text: App.formUpstream
            placeholderText: "http://127.0.0.1:8080"
            onAccepted: App.submit(subField.text, domainBox.currentIndex, pathField.text, upstreamField.text)
        }
        // a stack's published port fills the upstream
        Flex {
            direction: Tui.Horizontal
            visible: App.formHasPorts
            Text { text: qsTrId("autopanel.label.form.stackPort") }
            Text { text: " " }
            ComboBox { id: portBox; model: App.formPorts; textRole: "label"; maxWidth: 48; toolTipText: App.tipFormPort
                       onActivated: App.pickUpstream(index) }
        }
        Text { text: App.formError; visible: App.formErrorShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button {
            text: qsTrId("autopanel.button.form.save")
            toolTipText: App.tipFormSave
            DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
            onClicked: App.submit(subField.text, domainBox.currentIndex, pathField.text, upstreamField.text)
        }
        Button { text: qsTrId("autopanel.button.dialog.cancel"); toolTipText: App.tipDialogCancel; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
}
