// About.qml — what AutoPanel is, the panel's version and the running
// daemon's, the licence and where the source is. Each label is bold, its
// value beside it. Close, q, Enter and Escape close it.

Dialog {
    title: "About AutoPanel"
    closeOnQ: true
    width: 64
    standardButtons: Dialog.Close
    defaultButton: Dialog.Close

    Flex {
        direction: Tui.Vertical
        Text { text: App.aboutHeadline; font.bold: true }
        Text { text: "A lightweight control plane for self-hosted web services."; wrapMode: Tui.WordWrap }
        Text { text: "" }
        Flex { direction: Tui.Horizontal; Text { text: "Panel    "; font.bold: true } Text { text: App.aboutPanel } }
        Flex { direction: Tui.Horizontal; Text { text: "Daemon   "; font.bold: true } Text { text: App.aboutDaemon } }
        Flex { direction: Tui.Horizontal; Text { text: "Licence  "; font.bold: true } Text { text: "Apache-2.0" } }
        Flex { direction: Tui.Horizontal; Text { text: "Source   "; font.bold: true } Text { text: "https://github.com/yongjohnlee80/autopanel" } }
    }
}
