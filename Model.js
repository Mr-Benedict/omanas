.pragma library

// Formatting for the panel. Pure functions, no QML types, so they can be
// reasoned about (and tested) without a running shell.

function formatBytes(bytes, digits) {
  var value = Number(bytes) || 0
  if (value <= 0) return "0 B"
  var units = ["B", "KB", "MB", "GB", "TB", "PB"]
  var index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  var scaled = value / Math.pow(1024, index)
  var places = digits === undefined ? (scaled < 10 && index > 0 ? 1 : 0) : digits
  return scaled.toFixed(places) + " " + units[index]
}

function formatRate(bytesPerSecond) {
  var value = Number(bytesPerSecond) || 0
  if (value < 1) return "0"
  return formatBytes(value, value < 1024 * 1024 ? 0 : 1) + "/s"
}

function formatUptime(seconds) {
  var total = Math.max(0, Math.floor(Number(seconds) || 0))
  var days = Math.floor(total / 86400)
  var hours = Math.floor((total % 86400) / 3600)
  var minutes = Math.floor((total % 3600) / 60)
  if (days > 0) return days + "d " + hours + "h"
  if (hours > 0) return hours + "h " + minutes + "m"
  return minutes + "m"
}

function usageText(used, total) {
  if (!total) return formatBytes(used)
  return formatBytes(used) + " of " + formatBytes(total)
}

// One word for the whole NAS, from the worst thing it reports. The bar icon
// shows this, so it has to be conservative: anything not plainly healthy is
// worth the user's attention.
function healthOf(storage) {
  var volumes = (storage && storage.volumes) || []
  var disks = (storage && storage.disks) || []
  var worst = "ok"

  function raise(level) {
    if (level === "critical") worst = "critical"
    else if (level === "warning" && worst !== "critical") worst = "warning"
  }

  for (var i = 0; i < volumes.length; i++) {
    var status = String(volumes[i].status || "").toLowerCase()
    if (status === "crashed" || status === "danger") raise("critical")
    else if (status && status !== "normal") raise("warning")
    if (Number(volumes[i].percent) >= 90) raise("warning")
  }
  for (var j = 0; j < disks.length; j++) {
    var smart = String(disks[j].smart || "").toLowerCase()
    var diskStatus = String(disks[j].status || "").toLowerCase()
    if (smart === "critical" || diskStatus === "crashed") raise("critical")
    else if (disks[j].warning || (smart && smart !== "normal")) raise("warning")
  }
  return worst
}

function healthLabel(health, system) {
  if (health === "critical") return "Attention needed"
  if (health === "warning") return "Degraded"
  var temp = system && system.tempC
  return temp ? "Healthy · " + temp + "°C" : "Healthy"
}

// Longest first, so a share list does not jitter as values change width.
function pad(list, size) {
  var out = (list || []).slice(-size)
  while (out.length < size) out.unshift(0)
  return out
}
