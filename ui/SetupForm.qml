import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui

// The first thing the panel shows: where the NAS is, and who you are.
//
// The password lives in this form's field while it is being typed and is
// wiped the moment it has been handed to the helper. It is never written to
// shell.json and never read back out of the keyring into QML.
Item {
  id: root

  property color foreground: Color.foreground
  property string fontFamily: Style.font.family
  property bool busy: false
  property bool needsOtp: false
  property string errorField: ""
  property string errorText: ""

  readonly property color dim: Qt.darker(foreground, 1.55)

  signal submitted(string host, string port, bool https, string user, string password, string otp)

  implicitHeight: column.implicitHeight

  function clearPassword() {
    passwordField.text = ""
    otpField.text = ""
  }

  function focusFirstField() {
    if (hostField.text.length === 0) hostField.forceActiveFocus()
    else if (needsOtp) otpField.forceActiveFocus()
    else passwordField.forceActiveFocus()
  }

  // A two-factor login is two round trips: the first is refused with "code
  // required", the second carries the code. The password has to survive that
  // gap, so it is cleared when the connection succeeds rather than on submit.
  onNeedsOtpChanged: if (needsOtp) otpField.forceActiveFocus()

  function submit() {
    if (busy) return
    if (hostField.text.trim().length === 0) { hostField.forceActiveFocus(); return }
    if (userField.text.trim().length === 0) { userField.forceActiveFocus(); return }
    root.submitted(hostField.text.trim(), portField.text.trim(), httpsToggle.checked,
                   userField.text.trim(), passwordField.text, otpField.text.trim())
  }

  Column {
    id: column
    width: parent.width
    spacing: Style.space(10)

    Text {
      width: parent.width
      text: "Connect to your Synology NAS"
      textFormat: Text.PlainText
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.heading
    }

    Text {
      width: parent.width
      text: "Use a DSM account in the administrators group for health, resource and log data."
      textFormat: Text.PlainText
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Field {
      id: hostField
      label: "Address"
      placeholder: "192.168.1.20 or nas.local"
      highlighted: root.errorField === "host"
      onAccepted: userField.forceActiveFocus()
    }

    RowLayout {
      width: parent.width
      spacing: Style.space(10)

      Field {
        id: portField
        label: "Port"
        placeholder: httpsToggle.checked ? "5001" : "5000"
        Layout.preferredWidth: Style.space(90)
      }

      Item {
        Layout.fillWidth: true
        implicitHeight: httpsRow.implicitHeight

        Row {
          id: httpsRow
          anchors.left: parent.left
          anchors.bottom: parent.bottom
          anchors.bottomMargin: Style.space(4)
          spacing: Style.space(8)

          ToggleSwitch {
            id: httpsToggle
            checked: true
            foreground: root.foreground
            anchors.verticalCenter: parent.verticalCenter
          }

          Text {
            text: "HTTPS"
            textFormat: Text.PlainText
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            anchors.verticalCenter: parent.verticalCenter
          }
        }
      }
    }

    Field {
      id: userField
      label: "DSM account"
      placeholder: "admin"
      onAccepted: passwordField.forceActiveFocus()
    }

    Field {
      id: passwordField
      label: "Password"
      password: true
      highlighted: root.errorField === "password"
      onAccepted: root.needsOtp ? otpField.forceActiveFocus() : root.submit()
    }

    Field {
      id: otpField
      label: "Two-factor code"
      placeholder: "123456"
      visible: root.needsOtp
      highlighted: root.errorField === "otp"
      onAccepted: root.submit()
    }

    Text {
      width: parent.width
      visible: root.errorText.length > 0
      text: root.errorText
      textFormat: Text.PlainText
      color: Color.urgent
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Button {
      width: parent.width
      text: root.busy ? "Connecting…" : (root.needsOtp ? "Verify code" : "Connect")
      bordered: true
      foreground: root.foreground
      enabled: !root.busy
      onClicked: root.submit()
    }

    Text {
      width: parent.width
      text: "A self-signed certificate is fine. Omanas records its fingerprint and warns you if it ever changes."
      textFormat: Text.PlainText
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }
  }

  // A labelled input. Declared here rather than as its own file because it
  // is meaningless outside this form.
  component Field: Item {
    id: field

    property string label: ""
    property string placeholder: ""
    property bool password: false
    property bool highlighted: false
    property alias text: input.text

    signal accepted()

    width: column ? column.width : 0
    implicitHeight: fieldColumn.implicitHeight

    Column {
      id: fieldColumn
      width: parent.width
      spacing: Style.spacing.labelGap

      Text {
        text: field.label
        textFormat: Text.PlainText
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }

      TextField {
        id: input
        width: parent.width
        password: field.password
        placeholderText: field.placeholder
        foreground: root.foreground
        accent: field.highlighted ? Color.urgent : Color.accent
        onAccepted: field.accepted()
      }
    }
  }
}
