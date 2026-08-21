package app

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/model"
)

type dashboardData struct {
	Metrics     metricsSnapshot
	GeneratedAt string
	Healthy     bool
	TotalEdges  int
}

var routerDashboardTemplate = template.Must(template.New("router-dashboard").Funcs(template.FuncMap{
	"duration": func(value time.Duration) string {
		if value <= 0 {
			return "-"
		}
		return value.Round(time.Millisecond).String()
	},
	"stateClass": func(state model.EdgeState) string {
		switch state {
		case model.EdgeStateHealthy:
			return "state-up"
		case model.EdgeStateStarting:
			return "state-warn"
		default:
			return "state-down"
		}
	},
	"lastWin": func(value time.Time) string {
		if value.IsZero() {
			return "-"
		}
		return value.UTC().Format("15:04:05")
	},
}).Parse(routerDashboardHTML))

func writeDashboard(writer http.ResponseWriter, snapshots snapshotSource) {
	metrics := metricsSnapshot{
		Edges: snapshots.edgeSnapshot(),
		TCP:   snapshots.tcpSnapshot(),
		UDP:   snapshots.udpSnapshot(),
	}
	data := dashboardData{
		Metrics:     metrics,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Healthy:     metrics.Edges.Healthy >= minimumHealthyEdges,
		TotalEdges:  len(metrics.Edges.Edges),
	}
	var rendered bytes.Buffer
	if err := routerDashboardTemplate.Execute(&rendered, data); err != nil {
		http.Error(writer, fmt.Sprintf("render dashboard: %v", err), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(rendered.Bytes())
}

const routerDashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxygen Router Management</title>
<style>
html,body{margin:0;padding:0;background:#d6d3cb;color:#111;font:11px Verdana,Arial,sans-serif}
body{padding:18px 0}.shell{width:780px;margin:0 auto;border:1px solid #222;background:#eee;box-shadow:2px 2px 0 #777}
.brand{height:54px;background:#12345b;color:#fff;border-bottom:4px solid #e6b800;position:relative}
.brand h1{font:bold 20px Arial,sans-serif;margin:0;padding:12px 16px 0;letter-spacing:1px}.brand p{margin:2px 16px;color:#b9d2eb}
.system-led{position:absolute;right:16px;top:15px;background:#e5e5e5;color:#111;border:1px inset #fff;padding:6px 9px;font-weight:bold}.led{display:inline-block;width:9px;height:9px;margin-right:5px;border:1px solid #222;vertical-align:-1px}.led-up{background:#34a534}.led-down{background:#c52d2d}
.nav{background:#c5c5c5;border-bottom:1px solid #777;padding:5px 8px}.nav a{display:inline-block;padding:4px 12px;margin-right:3px;color:#001e43;text-decoration:none;border:1px outset #f8f8f8;background:#ddd;font-weight:bold}.nav a:active{border-style:inset}
.content{padding:10px}.panel{border:1px solid #777;background:#f5f5f1;margin-bottom:10px}.panel-title{background:#345b84;color:#fff;font-weight:bold;padding:5px 7px;border-bottom:1px solid #17324f}.panel-body{padding:8px}
.summary{width:100%;border-collapse:collapse}.summary td{width:25%;border-right:1px solid #aaa;padding:6px 10px;background:#e7e7df}.summary td:last-child{border-right:0}.label{display:block;color:#555;font-size:10px}.value{display:block;font:bold 17px Arial,sans-serif;color:#12345b;margin-top:2px}
table.grid{width:100%;border-collapse:collapse;background:#fff}table.grid th{background:#d2d2cb;border:1px solid #888;padding:5px;text-align:left;color:#222}table.grid td{border:1px solid #aaa;padding:5px}.numeric{text-align:right;font-family:"Courier New",monospace}.state{font-weight:bold;text-transform:uppercase}.state-up{color:#147214}.state-warn{color:#9a6500}.state-down{color:#a00000}.empty{text-align:center;color:#666;padding:14px!important}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:10px}.counter-table{width:100%;border-collapse:collapse}.counter-table td{padding:4px 6px;border-bottom:1px dotted #999}.counter-table td:last-child{text-align:right;font:bold 12px "Courier New",monospace;color:#12345b}
.footer{border-top:1px solid #888;background:#c5c5c5;padding:7px 10px;color:#333}.footer .right{float:right}.notice{margin-top:7px;padding:6px;border:1px solid #b5a100;background:#fff7bf;color:#554b00}
@media(max-width:820px){body{padding:0}.shell{width:auto;margin:0;border-left:0;border-right:0}.two-col{grid-template-columns:1fr}.summary td{display:block;width:auto;border-right:0;border-bottom:1px solid #aaa}.system-led{position:static;float:right;margin:-35px 10px 0 0}}
</style>
</head>
<body>
<div class="shell">
  <div class="brand">
    <h1>PROXYGEN</h1>
    <p>WireGuard Edge Router Management</p>
    <div class="system-led"><span class="led {{if .Healthy}}led-up{{else}}led-down{{end}}"></span>{{if .Healthy}}ONLINE{{else}}NO HEALTHY EDGE{{end}}</div>
  </div>
  <div class="nav"><a href="#status">Status</a><a href="#interfaces">Interfaces</a><a href="#traffic">Traffic</a><a href="/api/metrics">Raw Data</a><a href="/healthz">Health</a></div>
  <div class="content">
    <div class="panel" id="status">
      <div class="panel-title">System Status</div>
      <div class="panel-body" style="padding:0">
        <table class="summary"><tr>
          <td><span class="label">Router State</span><span class="value">{{if .Healthy}}READY{{else}}DEGRADED{{end}}</span></td>
          <td><span class="label">Healthy Edges</span><span class="value">{{.Metrics.Edges.Healthy}} / {{.TotalEdges}}</span></td>
          <td><span class="label">Active TCP</span><span class="value">{{.Metrics.TCP.Active}}</span></td>
          <td><span class="label">UDP NAT Entries</span><span class="value">{{.Metrics.UDP.Mappings}}</span></td>
        </tr></table>
      </div>
    </div>

    <div class="panel" id="interfaces">
      <div class="panel-title">WireGuard Edge Interfaces</div>
      <div class="panel-body">
        <table class="grid">
          <thead><tr><th>Interface</th><th>Link Status</th><th class="numeric">Probe RTT</th><th class="numeric">Attempts / Wins</th><th class="numeric">Last Win / RTT</th><th class="numeric">Failures</th></tr></thead>
          <tbody>
          {{range .Metrics.Edges.Edges}}<tr><td><strong>{{.ID}}</strong></td><td><span class="state {{stateClass .State}}">{{.State}}</span></td><td class="numeric">{{duration .ProbeRTT}}</td><td class="numeric">{{.TCPAttempts}} / {{.TCPWins}}</td><td class="numeric">{{lastWin .LastTCPWin}} / {{duration .LastTCPConnectRTT}}</td><td class="numeric">{{.ConsecutiveFailures}}</td></tr>
          {{else}}<tr><td class="empty" colspan="6">No edge interface is registered.</td></tr>{{end}}
          </tbody>
        </table>
      </div>
    </div>

    <div class="two-col" id="traffic">
      <div class="panel"><div class="panel-title">TCP Connection Racing</div><div class="panel-body"><table class="counter-table">
        <tr><td>Admissions</td><td>{{.Metrics.TCP.Admissions}}</td></tr><tr><td>Active Sessions</td><td>{{.Metrics.TCP.Active}}</td></tr><tr><td>Winning Races</td><td>{{.Metrics.TCP.Wins}}</td></tr><tr><td>Failed Races</td><td>{{.Metrics.TCP.Failures}}</td></tr><tr><td>ACL Denied</td><td>{{.Metrics.TCP.Denied}}</td></tr>
      </table></div></div>
      <div class="panel"><div class="panel-title">UDP NAT Table</div><div class="panel-body"><table class="counter-table">
        <tr><td>Active Mappings</td><td>{{.Metrics.UDP.Mappings}}</td></tr><tr><td>Expired Mappings</td><td>{{.Metrics.UDP.Expired}}</td></tr><tr><td>Dropped Packets</td><td>{{.Metrics.UDP.Dropped}}</td></tr><tr><td>ACL Denied</td><td>{{.Metrics.UDP.Denied}}</td></tr>
      </table><div class="notice">Read-only management panel. Restrict public access with host firewall rules.</div></div></div>
    </div>
  </div>
  <div class="footer"><span>Firmware: proxygen / Go runtime</span><span class="right">Last update: {{.GeneratedAt}} &middot; refresh 5s</span><div style="clear:both"></div></div>
</div>
</body>
</html>`
