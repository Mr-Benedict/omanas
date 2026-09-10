import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model
import "ui" as UI

// Bar widget and popout panel.
//
// The panel renders whatever the helper managed to fetch. A DSM that does not
// expose an API leaves its section out rather than showing a control that
// fails when pressed, so the same plugin works across DSM versions.
Panel {
  id: root
  moduleName: "io.github.mr-benedict.omanas"
  ipcTarget: "omanas"
  manageIpc: false

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property string barHealth: nas.connected ? nas.health : "offline"
  readonly property color barIconColor: nas.connected ? barForeground : Qt.darker(barForeground, 1.5)

  property int shareIndex: 0
  property bool cursorActive: false
  // Which share is showing its passphrase prompt, by name. Only one at a
  // time: the prompt is a modal step, not a per-row control.
  property string unlockingShare: ""

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function selectedShare() {
    if (nas.shares.length === 0) return null
    return nas.shares[Math.max(0, Math.min(shareIndex, nas.shares.length - 1))]
  }

  function moveCursor(dx, dy) {
    cursorActive = true
    if (dy === 0 || nas.shares.length === 0) return
    shareIndex = Math.max(0, Math.min(nas.shares.length - 1, shareIndex + dy))
  }

  function activateCursor() {
    var share = selectedShare()
    if (!share) return
    toggleShare(share)
  }

  function toggleShare(share) {
    if (!share) return
    if (share.mounted) nas.unmountShare(share.name)
    else if (share.locked) unlockingShare = share.name
    else nas.mountShare(share.name, false, false)
  }

  onOpenedChanged: {
    nas.panelOpen = opened
    if (!opened && setupForm) setupForm.clearPassword()
    if (opened) {
      cursorActive = false
      unlockingShare = ""
      if (panelFlick) panelFlick.contentY = 0
      nas.refresh()
      Qt.callLater(function() {
        if (nas.configured && nas.connected) keyCatcher.forceActiveFocus()
        else setupForm.focusFirstField()
      })
    }
  }

  Service {
    id: nas
    settings: root.settings
    // The setup form holds the typed password across a two-factor round
    // trip; once there is a session, that copy has no reason to exist.
    onConnectedChanged: if (connected && setupForm) setupForm.clearPassword()
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { nas.refresh(); return "ok" }
    function status(): string { return nas.connected ? nas.health : "offline" }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: Component {
      Item {
        NasIcon {
          anchors.centerIn: parent
          iconSize: Style.space(13)
          color: root.barIconColor
          health: root.barHealth
        }
      }
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) nas.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(400))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(620))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // While a text field owns the keyboard, single-letter shortcuts would
      // eat what the user is typing.
      blocked: !nas.connected || root.unlockingShare !== ""
      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return }
        root.moveCursor(dx, dy)
      }
      onActivateRequested: if (root.cursorActive) root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        var key = String(t).toLowerCase()
        if (key === "r") nas.refresh()
        else if (key === "d") nas.copyDiagnostics()
        else if (key === "o") nas.openMountpoint(root.selectedShare())
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          // Inset by a pixel each side. The Flickable clips, and a control
          // with a 1px border sitting flush at x=0 loses that border to the
          // clip boundary -- visible on the setup form's fields, where the
          // right border drew and the left did not.
          x: 1
          width: panelFlick.width - 2
          spacing: Style.space(12)

          // -- setup ---------------------------------------------------

          UI.SetupForm {
            id: setupForm
            width: parent.width
            visible: !nas.connected
            foreground: root.foreground
            fontFamily: root.fontFamily
            busy: nas.busy
            needsOtp: nas.needsOtp
            errorField: nas.errorField
            errorText: nas.lastError
            onSubmitted: function(host, port, https, user, password, otp) {
              nas.connectTo(host, port, https, user, password, otp)
            }
          }

          // -- header --------------------------------------------------

          PanelHero {
            width: parent.width
            visible: nas.connected
            title: nas.system.model ? String(nas.system.model) : "Synology NAS"
            meta: Model.healthLabel(nas.health, nas.system)
            detail: nas.system.version
                    ? String(nas.system.version) + " · up " + Model.formatUptime(nas.system.uptimeSec)
                    : nas.host
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconComponent: Component {
              NasIcon {
                iconSize: Style.font.display
                color: root.foreground
                health: nas.health
              }
            }
          }

          Text {
            width: parent.width
            visible: nas.connected && (nas.actionStatus !== "" || nas.lastError !== "")
            text: nas.actionStatus !== "" ? nas.actionStatus : nas.lastError
            textFormat: Text.PlainText
            color: nas.lastError !== "" && nas.actionStatus === "" ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // -- storage -------------------------------------------------

          Column {
            width: parent.width
            visible: nas.connected && storageRepeater.count > 0
            spacing: Style.space(10)

            PanelSectionHeader {
              text: "STORAGE"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              id: storageRepeater
              model: nas.storage.volumes || []

              UI.UsageBar {
                required property var modelData
                width: column.width
                label: String(modelData.label || modelData.id || "Volume")
                detail: Model.usageText(modelData.usedBytes, modelData.totalBytes)
                percent: Number(modelData.percent) || 0
                alarming: String(modelData.status || "").toLowerCase() !== "normal"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }
            }

            Text {
              width: parent.width
              visible: diskSummary.length > 0
              text: diskSummary
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption

              readonly property string diskSummary: {
                var disks = nas.storage.disks || []
                if (disks.length === 0) return ""
                var warned = 0
                var hottest = 0
                for (var i = 0; i < disks.length; i++) {
                  if (disks[i].warning || String(disks[i].smart || "").toLowerCase() !== "normal") warned++
                  hottest = Math.max(hottest, Number(disks[i].tempC) || 0)
                }
                var text = disks.length + (disks.length === 1 ? " disk" : " disks")
                if (warned > 0) text += " · " + warned + " needing attention"
                if (hottest > 0) text += " · up to " + hottest + "°C"
                return text
              }
            }
          }

          // -- resources -----------------------------------------------

          Column {
            width: parent.width
            visible: nas.connected && nas.capabilities.utilisation === true
            spacing: Style.space(8)

            PanelSectionHeader {
              text: "RESOURCES"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            RowLayout {
              width: parent.width
              spacing: Style.space(12)

              Meter {
                Layout.fillWidth: true
                label: "CPU"
                value: Number(nas.utilisation.cpuPercent) || 0
                history: nas.cpuHistory
              }

              Meter {
                Layout.fillWidth: true
                label: "Memory"
                value: Number(nas.utilisation.memPercent) || 0
                history: nas.memHistory
              }
            }

            Text {
              width: parent.width
              text: "↓ " + Model.formatRate(nas.utilisation.netRxBps)
                    + "   ↑ " + Model.formatRate(nas.utilisation.netTxBps)
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }
          }

          // -- shares --------------------------------------------------

          Column {
            width: parent.width
            visible: nas.connected && nas.capabilities.shares === true
            spacing: Style.space(6)

            PanelSectionHeader {
              text: "SHARED FOLDERS"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              width: parent.width
              visible: nas.shares.length === 0
              text: "No shared folders visible to this account."
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              horizontalAlignment: Text.AlignHCenter
            }

            Repeater {
              model: nas.shares

              ShareRow {
                required property var modelData
                required property int index
                width: column.width
                share: modelData
                rowIndex: index
              }
            }
          }

          // -- logs ----------------------------------------------------

          Column {
            width: parent.width
            visible: nas.connected && nas.logs.length > 0
            spacing: Style.space(6)

            PanelSectionHeader {
              text: "RECENT LOGS"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              model: nas.logs

              Item {
                required property var modelData
                width: column.width
                implicitHeight: logText.implicitHeight + Style.space(4)

                Rectangle {
                  width: Style.space(3)
                  height: logText.implicitHeight
                  radius: width / 2
                  anchors.left: parent.left
                  anchors.top: parent.top
                  color: {
                    var level = String(modelData.level || "").toLowerCase()
                    if (level.indexOf("err") >= 0 || level.indexOf("crit") >= 0) return root.urgent
                    if (level.indexOf("warn") >= 0) return Qt.lighter(root.urgent, 1.4)
                    return Qt.darker(root.foreground, 2.2)
                  }
                }

                Text {
                  id: logText
                  anchors.left: parent.left
                  anchors.leftMargin: Style.space(10)
                  anchors.right: parent.right
                  text: String(modelData.message || "")
                        + (modelData.time ? "  ·  " + String(modelData.time) : "")
                  textFormat: Text.PlainText
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  maximumLineCount: 2
                  elide: Text.ElideRight
                }
              }
            }
          }

          // -- footer --------------------------------------------------

          Column {
            width: parent.width
            visible: nas.connected
            spacing: Style.space(8)

            PanelSeparator { foreground: root.foreground }

            RowLayout {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Copy diagnostics"
                tooltipText: "A redacted report of what your DSM exposes, for a bug report"
                foreground: root.foreground
                fontSize: Style.font.bodySmall
                onClicked: nas.copyDiagnostics()
              }

              Item { Layout.fillWidth: true }

              Button {
                text: "Sign out"
                foreground: root.foreground
                fontSize: Style.font.bodySmall
                onClicked: nas.disconnect()
              }
            }
          }
        }
      }
    }
  }

  // A labelled percentage with its own history graph.
  component Meter: Item {
    id: meter

    property string label: ""
    property real value: 0
    property var history: []

    implicitHeight: meterColumn.implicitHeight

    Column {
      id: meterColumn
      width: parent.width
      spacing: Style.spacing.labelGap

      Item {
        width: parent.width
        implicitHeight: meterLabel.implicitHeight

        Text {
          id: meterLabel
          anchors.left: parent.left
          text: meter.label
          textFormat: Text.PlainText
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Text {
          anchors.right: parent.right
          text: Math.round(meter.value) + "%"
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }
      }

      UI.Sparkline {
        width: parent.width
        values: meter.history
        stroke: meter.value >= 90 ? root.urgent : Color.accent
      }
    }
  }

  // One shared folder: what it is, and what can be done with it.
  component ShareRow: Item {
    id: row

    property var share: null
    property int rowIndex: 0

    readonly property bool hasCursor: root.cursorActive && root.shareIndex === rowIndex
    readonly property bool isUnlocking: root.unlockingShare === String(share ? share.name : "")
    readonly property bool cryptoSupported: String(nas.capabilities.crypto || "") !== ""

    implicitHeight: rowColumn.implicitHeight + Style.space(8)

    CursorSurface {
      anchors.fill: parent
      hasCursor: row.hasCursor
      foreground: root.foreground
    }

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton
      cursorShape: Qt.PointingHandCursor
      onEntered: {
        root.cursorActive = true
        root.shareIndex = row.rowIndex
      }
      onClicked: root.toggleShare(row.share)
    }

    Column {
      id: rowColumn
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(6)

      RowLayout {
        width: parent.width
        spacing: Style.space(8)

        Text {
          text: row.share ? String(row.share.name) : ""
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
          Layout.fillWidth: true
        }

        Badge {
          visible: row.share && row.share.locked
          text: "locked"
          tone: root.urgent
        }

        Badge {
          visible: row.share && row.share.encrypted && !row.share.locked
          text: "encrypted"
          tone: Color.accent
        }

        Badge {
          visible: row.share && row.share.mounted
          text: "mounted"
          tone: Color.accent
        }
      }

      Text {
        width: parent.width
        visible: row.share && row.share.mounted && String(row.share.mountpoint || "") !== ""
        text: row.share ? String(row.share.mountpoint) : ""
        textFormat: Text.PlainText
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        elide: Text.ElideMiddle
      }

      // The passphrase prompt appears in place, only for the share being
      // unlocked, and is discarded whichever way it ends.
      Column {
        width: parent.width
        visible: row.isUnlocking
        spacing: Style.space(6)

        Text {
          width: parent.width
          text: row.cryptoSupported
                ? "Enter this folder's encryption passphrase. It is sent to the NAS and not stored."
                : "This DSM does not expose an unlock API. Unlock the folder in DSM, then mount it here."
          textFormat: Text.PlainText
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        TextField {
          id: passphrase
          width: parent.width
          password: true
          enabled: row.cryptoSupported
          placeholderText: "Encryption passphrase"
          foreground: root.foreground
          onAccepted: {
            // Wired once the probe confirms which API DSM serves.
            passphrase.text = ""
            root.unlockingShare = ""
          }
        }
      }

      RowLayout {
        width: parent.width
        spacing: Style.space(6)
        visible: row.hasCursor && !row.isUnlocking

        Button {
          visible: row.share && !row.share.mounted && !row.share.locked
          text: "Mount"
          fontSize: Style.font.caption
          foreground: root.foreground
          onClicked: nas.mountShare(row.share.name, false, false)
        }

        Button {
          visible: row.share && !row.share.mounted && !row.share.locked
          text: "Mount & keep"
          tooltipText: "Also add an /etc/fstab entry, so later mounts need no password"
          fontSize: Style.font.caption
          foreground: root.foreground
          onClicked: nas.mountShare(row.share.name, true, false)
        }

        Button {
          visible: row.share && row.share.locked
          text: "Unlock"
          fontSize: Style.font.caption
          foreground: root.foreground
          onClicked: root.unlockingShare = row.share.name
        }

        Button {
          visible: row.share && row.share.mounted
          text: "Open"
          fontSize: Style.font.caption
          foreground: root.foreground
          onClicked: nas.openMountpoint(row.share)
        }

        Button {
          visible: row.share && row.share.mounted
          text: "Unmount"
          fontSize: Style.font.caption
          foreground: root.foreground
          onClicked: nas.unmountShare(row.share.name)
        }

        Item { Layout.fillWidth: true }
      }
    }
  }

  component Badge: Rectangle {
    property string text: ""
    property color tone: Color.accent

    implicitWidth: badgeText.implicitWidth + Style.space(10)
    implicitHeight: badgeText.implicitHeight + Style.space(4)
    radius: Style.cornerRadius > 0 ? Style.cornerRadius : implicitHeight / 2
    color: Qt.rgba(tone.r, tone.g, tone.b, 0.16)

    Text {
      id: badgeText
      anchors.centerIn: parent
      text: parent.text
      textFormat: Text.PlainText
      color: parent.tone
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
  }
}
