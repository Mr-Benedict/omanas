import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model

// All plugin state, and the only place that starts a process.
//
// Nothing here talks to the NAS directly. Every call goes through the bin/
// helpers, which own the credentials. That keeps secrets out of the QML
// scene, which the shell shares with every other installed plugin.
Item {
  id: root

  property var settings: ({})
  property bool panelOpen: false

  readonly property string helperPath: Qt.resolvedUrl("bin/omanas").toString().replace(/^file:\/\//, "")

  // Connection lifecycle
  property bool configured: false
  property bool connected: false
  property bool busy: false
  property bool needsOtp: false
  property string lastError: ""
  property string errorField: ""
  property string actionStatus: ""
  property string host: ""

  // What this particular DSM can do. The panel hides controls it cannot
  // honour rather than offering a button that fails when pressed.
  property var capabilities: ({})

  property var system: ({})
  property var storage: ({ volumes: [], disks: [] })
  property var utilisation: ({})
  property var shares: []
  property var logs: []
  property var sectionErrors: ({})

  // Sparkline history. Kept here rather than in the panel so it survives the
  // panel being closed and reopened.
  property var cpuHistory: []
  property var memHistory: []
  readonly property int historyLength: 40

  readonly property string health: Model.healthOf(storage)
  readonly property bool hasShares: shares.length > 0

  readonly property int refreshIntervalSec: intSetting("refreshIntervalSec", 60, 10, 3600)
  readonly property int resourcePollSec: intSetting("resourcePollSec", 3, 1, 30)
  readonly property int logCount: intSetting("logCount", 10, 0, 100)
  readonly property string mountRoot: String(setting("mountRoot", "~/mnt/nas"))

  signal diagnosticsReady(string report)
  signal unlocked(string share)

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function intSetting(name, fallback, min, max) {
    var n = parseInt(String(setting(name, fallback)), 10)
    if (!isFinite(n)) n = fallback
    return Math.max(min, Math.min(max, n))
  }

  // -- reading ---------------------------------------------------------

  function refresh() {
    if (statusProcess.running) return
    busy = true
    statusProcess.command = [helperPath, "status", "--logs", String(logCount)]
    statusProcess.running = true
  }

  function applyStatus(raw) {
    var parsed
    try {
      parsed = JSON.parse(String(raw || "").trim())
    } catch (e) {
      lastError = "The helper returned something unreadable"
      return
    }

    configured = parsed.configured !== false
    if (!configured) {
      connected = false
      return
    }
    if (!parsed.ok) {
      connected = false
      needsOtp = parsed.needsOtp === true
      lastError = String(parsed.error || "Could not reach the NAS")
      return
    }

    connected = true
    needsOtp = false
    lastError = ""
    host = String(parsed.host || host)
    capabilities = parsed.capabilities || ({})
    sectionErrors = parsed.errors || ({})
    if (parsed.system) system = parsed.system
    if (parsed.storage) storage = parsed.storage
    if (parsed.shares) shares = parsed.shares
    if (parsed.logs) logs = parsed.logs
    if (parsed.utilisation) recordUtilisation(parsed.utilisation)
  }

  function recordUtilisation(sample) {
    utilisation = sample
    var cpu = cpuHistory.slice(-(historyLength - 1))
    var mem = memHistory.slice(-(historyLength - 1))
    cpu.push(Number(sample.cpuPercent) || 0)
    mem.push(Number(sample.memPercent) || 0)
    cpuHistory = cpu
    memHistory = mem
  }

  // -- connecting ------------------------------------------------------

  // Held only between pressing Connect and the helper starting, then wiped.
  // The user has to type the password into a QML field, so it cannot avoid
  // existing here for a moment; what it must never do is persist or be read
  // back out of the keyring into QML later.
  property string _pendingPassword: ""

  function connectTo(hostValue, portValue, useHttps, userValue, password, otp) {
    if (connectProcess.running) return
    busy = true
    lastError = ""
    errorField = ""
    actionStatus = "Connecting…"
    _pendingPassword = String(password || "")

    var argv = [helperPath, "connect", "--host", String(hostValue), "--user", String(userValue)]
    if (portValue) argv.push("--port", String(portValue))
    if (!useHttps) argv.push("--no-https")
    if (otp) argv.push("--otp", String(otp))
    connectProcess.command = argv
    connectProcess.running = true
  }

  function applyConnect(raw) {
    var parsed
    try {
      parsed = JSON.parse(String(raw || "").trim())
    } catch (e) {
      lastError = "The helper returned something unreadable"
      actionStatus = ""
      return
    }
    if (parsed.ok) {
      configured = true
      connected = true
      needsOtp = false
      lastError = ""
      errorField = ""
      actionStatus = ""
      capabilities = parsed.capabilities || ({})
      host = String(parsed.host || "")
      refresh()
      return
    }
    needsOtp = parsed.needsOtp === true
    errorField = String(parsed.field || "")
    lastError = String(parsed.error || "Could not connect")
    actionStatus = ""
  }

  function disconnect() {
    if (actionProcess.running) return
    actionProcess.command = [helperPath, "logout"]
    actionProcess.running = true
    connected = false
    shares = []
    logs = []
  }

  // -- mounting --------------------------------------------------------

  function shareByName(name) {
    for (var i = 0; i < shares.length; i++) if (shares[i].name === name) return shares[i]
    return null
  }

  function runAction(argv, status) {
    if (actionProcess.running) return
    actionStatus = status
    lastError = ""
    actionProcess.command = argv
    actionProcess.running = true
  }

  function mountShare(name, persist, readOnly) {
    var argv = [helperPath, "mount", "--share", String(name), "--mount-root", mountRoot]
    if (persist) argv.push("--persist")
    if (readOnly) argv.push("--read-only")
    runAction(argv, "Mounting " + name + "…")
  }

  function unmountShare(name) {
    runAction([helperPath, "unmount", "--share", String(name), "--mount-root", mountRoot],
              "Unmounting " + name + "…")
  }

  // Held only between pressing Unlock and the helper starting, then wiped.
  property string _pendingPassphrase: ""

  function unlockShare(name, passphrase) {
    if (unlockProcess.running) return
    _pendingPassphrase = String(passphrase || "")
    actionStatus = "Unlocking " + name + "…"
    lastError = ""
    unlockProcess.command = [helperPath, "unlock", "--share", String(name)]
    unlockProcess.running = true
  }

  function lockShare(name) {
    runAction([helperPath, "lock", "--share", String(name)], "Locking " + name + "…")
  }

  function forgetShare(name) {
    runAction([helperPath, "forget", "--share", String(name), "--mount-root", mountRoot],
              "Forgetting " + name + "…")
  }

  function openMountpoint(share) {
    if (!share || !share.mountpoint) return
    var parts = String(share.mountpoint).split("/")
    for (var i = 0; i < parts.length; i++) parts[i] = encodeURIComponent(parts[i])
    Quickshell.execDetached(["uwsm-app", "--", "xdg-open", "file://" + parts.join("/")])
  }

  function copyDiagnostics() {
    if (diagnosticsProcess.running) return
    actionStatus = "Collecting diagnostics…"
    diagnosticsProcess.command = [helperPath, "diagnostics"]
    diagnosticsProcess.running = true
  }

  // -- processes -------------------------------------------------------

  Process {
    id: statusProcess
    running: false
    command: []
    stdout: StdioCollector { id: statusOut; waitForEnd: true }
    stderr: StdioCollector { id: statusErr; waitForEnd: true }
    onExited: function(exitCode) {
      root.busy = false
      var out = String(statusOut.text || "")
      if (out.trim().length > 0) root.applyStatus(out)
      else {
        root.connected = false
        root.lastError = String(statusErr.text || "").trim() || "The helper produced no output"
      }
    }
  }

  Process {
    id: connectProcess
    running: false
    command: []
    stdinEnabled: true
    stdout: StdioCollector { id: connectOut; waitForEnd: true }
    stderr: StdioCollector { id: connectErr; waitForEnd: true }
    onStarted: {
      // One line, then stdin closes. The helper reads exactly one line, so
      // it never waits on a stream this side forgot to end.
      write(root._pendingPassword + "\n")
      stdinEnabled = false
      root._pendingPassword = ""
    }
    onExited: function(exitCode) {
      root.busy = false
      var out = String(connectOut.text || "")
      if (out.trim().length > 0) root.applyConnect(out)
      else {
        root.actionStatus = ""
        root.lastError = String(connectErr.text || "").trim() || "The helper produced no output"
      }
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: StdioCollector { id: actionOut; waitForEnd: true }
    stderr: StdioCollector { id: actionErr; waitForEnd: true }
    onExited: function(exitCode) {
      root.actionStatus = ""
      var parsed = null
      try {
        parsed = JSON.parse(String(actionOut.text || "").trim())
      } catch (e) {
        parsed = null
      }
      if (parsed && parsed.ok) root.lastError = ""
      else if (parsed && parsed.cancelled) root.lastError = ""
      else if (parsed) root.lastError = String(parsed.error || "That did not work")
      else if (exitCode !== 0) root.lastError = String(actionErr.text || "").trim() || "That did not work"
      // Mount state is read back from the system rather than assumed, so a
      // half-succeeded action still leaves the panel telling the truth.
      root.refresh()
    }
  }

  Process {
    id: unlockProcess
    running: false
    command: []
    stdinEnabled: true
    stdout: StdioCollector { id: unlockOut; waitForEnd: true }
    stderr: StdioCollector { id: unlockErr; waitForEnd: true }
    onStarted: {
      write(root._pendingPassphrase + "\n")
      stdinEnabled = false
      root._pendingPassphrase = ""
    }
    onExited: function(exitCode) {
      root.actionStatus = ""
      var parsed = null
      try {
        parsed = JSON.parse(String(unlockOut.text || "").trim())
      } catch (e) {
        parsed = null
      }
      if (parsed && parsed.ok) {
        root.lastError = ""
        root.unlocked(String(parsed.share || ""))
      } else if (parsed) {
        root.lastError = String(parsed.error || "Could not unlock the folder")
      } else {
        root.lastError = String(unlockErr.text || "").trim() || "Could not unlock the folder"
      }
      root.refresh()
    }
  }

  Process {
    id: utilProcess
    running: false
    command: []
    stdout: StdioCollector { id: utilOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode !== 0) return
      try {
        var parsed = JSON.parse(String(utilOut.text || "").trim())
        if (parsed.ok && parsed.utilisation) root.recordUtilisation(parsed.utilisation)
      } catch (e) {
        // A dropped sample is not worth surfacing; the next one is 2s away.
      }
    }
  }

  Process {
    id: diagnosticsProcess
    running: false
    command: []
    stdout: StdioCollector { id: diagOut; waitForEnd: true }
    onExited: function(exitCode) {
      root.actionStatus = ""
      var report = String(diagOut.text || "").trim()
      if (!report) {
        root.lastError = "Could not collect diagnostics"
        return
      }
      clipboardProcess.command = ["wl-copy", report]
      clipboardProcess.running = true
      root.diagnosticsReady(report)
      root.actionStatus = "Diagnostics copied to the clipboard"
      clearStatus.restart()
    }
  }

  Process { id: clipboardProcess; running: false; command: [] }

  Timer {
    id: clearStatus
    interval: 4000
    onTriggered: root.actionStatus = ""
  }

  // Full refresh on a slow cadence; it costs several API calls.
  Timer {
    interval: root.refreshIntervalSec * 1000
    running: root.connected
    repeat: true
    onTriggered: root.refresh()
  }

  // The live graphs poll on their own, only while someone is looking, and
  // only for the one cheap endpoint.
  Timer {
    interval: root.resourcePollSec * 1000
    running: root.panelOpen && root.connected && root.capabilities.utilisation === true
    repeat: true
    onTriggered: {
      if (!utilProcess.running) {
        utilProcess.command = [root.helperPath, "utilisation"]
        utilProcess.running = true
      }
    }
  }

  Component.onCompleted: refresh()
}
