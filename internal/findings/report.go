package findings

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"
)

type ReportData struct {
	GeneratedAt       string
	PagesScanned      int
	AttachmentsParsed int
	Duration          string
	TotalFindings     int
	Critical          int
	High              int
	Medium            int
	Low               int
	FindingsJSON      template.JS
}

// WriteHTMLReport reads findings from the JSONL file on disk (not memory) to
// avoid duplicating the entire findings set in RAM during report generation.
func WriteHTMLReport(path string, jsonlPath string, store *Store, pagesScanned, attachmentsParsed int, elapsed time.Duration) error {
	// Read findings from the JSONL file to avoid loading everything from the store.
	findingsJSON, totalFindings, counts, err := readFindingsFromJSONL(jsonlPath)
	if err != nil {
		return fmt.Errorf("read findings for report: %w", err)
	}

	// Fall back to store counts if JSONL was empty (e.g. no findings).
	if totalFindings == 0 {
		counts = store.CountBySeverity()
		totalFindings = store.Count()
		findingsJSON = []byte("[]")
	}

	rd := ReportData{
		GeneratedAt:       time.Now().Format("2006-01-02 15:04:05 MST"),
		PagesScanned:      pagesScanned,
		AttachmentsParsed: attachmentsParsed,
		Duration:          elapsed.Round(time.Second).String(),
		TotalFindings:     totalFindings,
		Critical:          counts[SeverityCritical],
		High:              counts[SeverityHigh],
		Medium:            counts[SeverityMedium],
		Low:               counts[SeverityLow],
		FindingsJSON:      template.JS(findingsJSON),
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	return reportTmpl.Execute(f, rd)
}

func readFindingsFromJSONL(path string) ([]byte, int, map[Severity]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	defer f.Close()

	var allFindings []json.RawMessage
	counts := make(map[Severity]int)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		allFindings = append(allFindings, append(json.RawMessage{}, line...))

		var partial struct {
			Severity Severity `json:"severity"`
		}
		json.Unmarshal(line, &partial)
		counts[partial.Severity]++
	}
	if err := sc.Err(); err != nil {
		return nil, 0, nil, err
	}

	data, err := json.Marshal(allFindings)
	if err != nil {
		return nil, 0, nil, err
	}
	return data, len(allFindings), counts, nil
}

var reportTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>confcred report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, sans-serif; background: #0f1117; color: #c9d1d9; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 16px; color: #e6edf3; }
  .meta { color: #8b949e; font-size: 13px; margin-bottom: 20px; }

  .stats { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 18px; min-width: 120px; }
  .stat .label { font-size: 11px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; }
  .stat .value { font-size: 22px; font-weight: 600; color: #e6edf3; }
  .stat.critical .value { color: #f85149; }
  .stat.high .value { color: #d29922; }
  .stat.medium .value { color: #58a6ff; }
  .stat.low .value { color: #8b949e; }

  .toolbar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
  .search { flex: 1; min-width: 200px; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; outline: none; }
  .search:focus { border-color: #58a6ff; }
  .search::placeholder { color: #484f58; }
  .filter-btn { padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; background: #161b22; color: #c9d1d9; font-size: 13px; cursor: pointer; }
  .filter-btn:hover { border-color: #58a6ff; }
  .filter-btn.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
  .count-badge { font-size: 13px; color: #8b949e; white-space: nowrap; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { text-align: left; padding: 8px 10px; border-bottom: 1px solid #30363d; color: #8b949e; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; background: #0f1117; cursor: pointer; user-select: none; }
  thead th:hover { color: #e6edf3; }
  thead th .arrow { margin-left: 4px; font-size: 10px; }
  tbody tr { border-bottom: 1px solid #21262d; }
  tbody tr:hover { background: #161b22; }
  td { padding: 8px 10px; vertical-align: top; }
  td.sev { font-weight: 600; text-transform: uppercase; font-size: 11px; white-space: nowrap; }
  td.sev.critical { color: #f85149; }
  td.sev.high { color: #d29922; }
  td.sev.medium { color: #58a6ff; }
  td.sev.low { color: #8b949e; }
  td.val { font-family: "SF Mono", "Fira Code", monospace; font-size: 12px; word-break: break-all; max-width: 300px; }
  td.ctx { color: #8b949e; font-size: 12px; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  td.ctx:hover { white-space: normal; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .att { color: #8b949e; font-size: 11px; }
  .conf { font-size: 11px; color: #8b949e; }
  .empty { text-align: center; padding: 40px; color: #484f58; }
</style>
</head>
<body>
<div class="container">
  <h1>confcred findings</h1>
  <div class="meta">Generated {{.GeneratedAt}} &middot; Duration {{.Duration}} &middot; {{.PagesScanned}} pages scanned &middot; {{.AttachmentsParsed}} attachments parsed</div>

  <div class="stats">
    <div class="stat"><div class="label">Total</div><div class="value">{{.TotalFindings}}</div></div>
    <div class="stat critical"><div class="label">Critical</div><div class="value">{{.Critical}}</div></div>
    <div class="stat high"><div class="label">High</div><div class="value">{{.High}}</div></div>
    <div class="stat medium"><div class="label">Medium</div><div class="value">{{.Medium}}</div></div>
    <div class="stat low"><div class="label">Low</div><div class="value">{{.Low}}</div></div>
  </div>

  <div class="toolbar">
    <input class="search" type="text" id="search" placeholder="Search findings (pattern, value, page, space...)">
    <button class="filter-btn active" data-sev="all">All</button>
    <button class="filter-btn" data-sev="critical">Critical</button>
    <button class="filter-btn" data-sev="high">High</button>
    <button class="filter-btn" data-sev="medium">Medium</button>
    <button class="filter-btn" data-sev="low">Low</button>
    <span class="count-badge" id="count"></span>
  </div>

  <table>
    <thead>
      <tr>
        <th data-col="severity">Sev <span class="arrow"></span></th>
        <th data-col="confidence">Conf <span class="arrow"></span></th>
        <th data-col="pattern">Pattern <span class="arrow"></span></th>
        <th data-col="value">Value <span class="arrow"></span></th>
        <th data-col="context">Context <span class="arrow"></span></th>
        <th data-col="location">Location <span class="arrow"></span></th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div class="empty" id="empty" style="display:none">No findings match your search.</div>
</div>

<script>
const findings = {{.FindingsJSON}};
const sevOrder = {critical:0, high:1, medium:2, low:3};
let activeSev = "all";
let sortCol = "severity";
let sortAsc = true;
let query = "";

const tbody = document.getElementById("tbody");
const countEl = document.getElementById("count");
const emptyEl = document.getElementById("empty");
const searchEl = document.getElementById("search");

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function render() {
  let rows = findings.filter(f => {
    if (activeSev !== "all" && f.severity !== activeSev) return false;
    if (!query) return true;
    const q = query.toLowerCase();
    return f.pattern.toLowerCase().includes(q) ||
           f.value.toLowerCase().includes(q) ||
           f.context.toLowerCase().includes(q) ||
           f.location.page_title.toLowerCase().includes(q) ||
           f.location.space_key.toLowerCase().includes(q) ||
           (f.location.attachment || "").toLowerCase().includes(q);
  });

  rows.sort((a, b) => {
    let va, vb;
    switch (sortCol) {
      case "severity": va = sevOrder[a.severity]; vb = sevOrder[b.severity]; break;
      case "confidence": va = a.confidence; vb = b.confidence; break;
      case "pattern": va = a.pattern.toLowerCase(); vb = b.pattern.toLowerCase(); break;
      case "value": va = a.value.toLowerCase(); vb = b.value.toLowerCase(); break;
      case "context": va = a.context.toLowerCase(); vb = b.context.toLowerCase(); break;
      case "location": va = a.location.page_title.toLowerCase(); vb = b.location.page_title.toLowerCase(); break;
      default: va = 0; vb = 0;
    }
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  countEl.textContent = rows.length + " of " + findings.length + " findings";
  emptyEl.style.display = rows.length === 0 ? "" : "none";

  const html = rows.map(f => {
    const loc = f.location;
    const att = loc.source === "attachment" ? '<div class="att">&#128206; ' + escapeHtml(loc.attachment) + '</div>' : '';
    return '<tr>' +
      '<td class="sev ' + f.severity + '">' + f.severity + '</td>' +
      '<td class="conf">' + f.confidence + '</td>' +
      '<td>' + escapeHtml(f.pattern) + '</td>' +
      '<td class="val">' + escapeHtml(f.value) + '</td>' +
      '<td class="ctx" title="' + escapeHtml(f.context) + '">' + escapeHtml(f.context) + '</td>' +
      '<td><a href="' + escapeHtml(loc.page_url) + '" target="_blank">' + escapeHtml(loc.page_title) + '</a>' +
        ' <span class="att">(' + escapeHtml(loc.space_key) + ')</span>' + att + '</td>' +
      '</tr>';
  }).join("");
  tbody.innerHTML = html;
}

searchEl.addEventListener("input", e => { query = e.target.value; render(); });

document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeSev = btn.dataset.sev;
    render();
  });
});

document.querySelectorAll("thead th[data-col]").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
    document.querySelectorAll("thead th .arrow").forEach(a => a.textContent = "");
    th.querySelector(".arrow").textContent = sortAsc ? "\u25B2" : "\u25BC";
    render();
  });
});

render();
</script>
</body>
</html>`))
