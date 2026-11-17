// PlanDialog.qml — System › Firewall › Turn on: what turning the firewall on
// would do, before it is done.
//
// The host fills the App.plan* sources from sys.firewall.plan, then opens it.
// Over the panes, the manager, the SSH ports allowed first and the time an
// enable waits for a confirm. On the left each listening port the firewall
// would block, ticked when it is to be allowed; on the right the selected one.
// Turn on enables as the plan showed (the plan's hash binds it).

Dialog {
    title: qsTrId("autopanel.title.dialog.plan")
    width: 100
    maxWidthPercent: 96
    maxHeightPercent: 90
    Flex {
        direction: Tui.Vertical
        Text { text: App.planSummary; wrapMode: Tui.WordWrap }
        Split {
            Layout.fillHeight: true
            orientation: Tui.Horizontal
            ratio: 0.5
            Frame {
                title: qsTrId("autopanel.title.pane.planPorts")
                TableView {
                    id: planTable
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.planRows
                    onCurrentIndexChanged: App.planMoved(index)
                    onActivated: App.planToggle()
                    TableViewColumn { role: "allow"; title: ""; width: 9 }
                    TableViewColumn { role: "port"; title: "PORT"; width: 12 }
                    TableViewColumn { role: "use"; title: "USE"; width: 0 }
                }
            }
            Frame {
                title: qsTrId("autopanel.title.pane.details")
                Text { text: App.planDetail; wrapMode: Tui.WordWrap }
            }
        }
    }
    DialogButtonBox {
        Button {
            text: App.planToggleText
            toolTipText: App.tipPlanToggle
            DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
            onClicked: App.planToggle()
        }
        Button {
            text: qsTrId("autopanel.button.plan.enable")
            toolTipText: App.tipPlanEnable
            enabled: App.planAllowed
            DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            onClicked: App.planAccept()
        }
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
}
