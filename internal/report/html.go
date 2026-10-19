package report

// HTML report — a single self-contained file with no external assets, so it
// can be emailed or opened from a USB stick on an air-gapped machine.
//
// Design goals:
//   - the verdict is readable in 2 seconds (colour + score, not just text)
//   - every file is one click from its full finding list
//   - filterable and sortable without any JavaScript framework
//
// All values are HTML-escaped: file paths and finding details come from
// scanned files, which is untrusted input.

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"gamecrack-scanner/internal/model"
)

// WriteHTML renders the scan summary as a standalone HTML document.
func WriteHTML(path string, sum *model.Summary, target string, toolVersion string) error {
	var flagged []model.FileResult
	clean := 0
	for _, r := range sum.Results {
		if r.Skipped {
			continue
		}
		if r.Verdict == model.VerdictClean {
			clean++
			continue
		}
		flagged = append(flagged, r)
	}
	sort.Slice(flagged, func(i, j int) bool {
		if flagged[i].Score != flagged[j].Score {
			return flagged[i].Score > flagged[j].Score
		}
		return flagged[i].Path < flagged[j].Path
	})

	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CrackSentinel report — ` + html.EscapeString(target) + `</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;
--mal:#f85149;--sus:#d29922;--cln:#3fb950;--acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,"Cascadia Code",Consolas,monospace}
header{padding:22px 26px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:18px;letter-spacing:.4px}
.sub{color:var(--mut);font-size:12px;word-break:break-all}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}
.card{background:#0d1117;border:1px solid var(--line);border-radius:8px;
padding:9px 15px;min-width:104px}
.card .n{font-size:22px;font-weight:700;line-height:1.1}
.card .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
.mal{color:var(--mal)}.sus{color:var(--sus)}.cln{color:var(--cln)}.acc{color:var(--acc)}
main{padding:18px 26px 60px}
.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
button{background:#21262d;color:var(--fg);border:1px solid var(--line);border-radius:6px;
padding:6px 13px;cursor:pointer;font:inherit;font-size:12px}
button:hover{border-color:var(--acc)}
button.on{background:var(--acc);color:#04121f;border-color:var(--acc);font-weight:600}
input{background:#0d1117;color:var(--fg);border:1px solid var(--line);border-radius:6px;
padding:6px 11px;font:inherit;font-size:12px;min-width:270px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;
letter-spacing:.6px;border-bottom:1px solid var(--line);padding:9px 10px;cursor:pointer;
white-space:nowrap;user-select:none}
th:hover{color:var(--acc)}
td{padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}
tr.row{cursor:pointer}
tr.row:hover td{background:#161b22}
tr.hide{display:none}
.vd{font-weight:700;white-space:nowrap}
.sc{display:inline-block;min-width:34px;text-align:center;border-radius:4px;
padding:1px 7px;font-weight:700;font-size:12px}
.sc.mal{background:rgba(248,81,73,.16);color:var(--mal)}
.sc.sus{background:rgba(210,153,34,.16);color:var(--sus)}
.sc.cln{background:rgba(63,185,80,.14);color:var(--cln)}
.p{color:var(--acc);word-break:break-all}
.hash{color:var(--mut);font-size:11px}
details{margin-top:7px}
summary{cursor:pointer;color:var(--acc);font-size:12px;outline:none}
.finding{display:grid;grid-template-columns:52px 128px 1fr;gap:9px;
padding:5px 0;border-bottom:1px dotted #21262d;font-size:12px}
.finding .sv{text-align:right;font-weight:700}
.finding .rg{color:var(--acc)}
.finding .ct{color:var(--mut);font-size:11px}
.finding .dt{color:var(--fg);word-break:break-word}
.empty{color:var(--mut);padding:40px;text-align:center}
footer{padding:16px 26px;color:var(--mut);font-size:11px;border-top:1px solid var(--line)}
@media(max-width:820px){.finding{grid-template-columns:44px 1fr}.finding .ct{grid-column:2}}
</style></head><body>
`)

	fmt.Fprintf(&b, "<h1>CrackSentinel report</h1>\n")
	fmt.Fprintf(&b, "<div class=\"sub\">target: %s<br>tool: %s &middot; generated: %s</div>\n",
		html.EscapeString(target), html.EscapeString(toolVersion), time.Now().Format("2006-01-02 15:04:05"))

	b.WriteString("<div class=\"cards\">")
	card := func(n int, label, cls string) {
		fmt.Fprintf(&b, "<div class=\"card\"><div class=\"n %s\">%d</div><div class=\"l\">%s</div></div>", cls, n, label)
	}
	card(sum.Malicious, "malicious", "mal")
	card(sum.Suspicious, "suspicious", "sus")
	card(clean, "clean", "cln")
	card(sum.FilesScanned, "scanned", "acc")
	card(sum.FilesSkipped, "skipped", "")
	fmt.Fprintf(&b, "<div class=\"card\"><div class=\"n acc\">%d</div><div class=\"l\">ms</div></div>", sum.DurationMs)
	b.WriteString("</div></main>")

	b.WriteString(`<main>
<div class="bar">
<button class="on" data-f="all">All</button>
<button data-f="malicious">Malicious</button>
<button data-f="suspicious">Suspicious</button>
<button data-f="clean">Clean</button>
<input id="q" placeholder="filter by path, rule or detail...">
<span class="sub" id="cnt"></span>
</div>
`)
	if len(flagged) == 0 && clean == 0 {
		b.WriteString(`<div class="empty">No files were scanned.</div>`)
	} else {
		b.WriteString(`<table id="tbl"><thead><tr>
<th data-s="0">Verdict</th><th data-s="1">Score</th><th data-s="2">File</th>
<th data-s="3">Type</th><th data-s="4">SHA-256</th><th data-s="5">Findings</th>
</tr></thead><tbody>
`)
		rows := append([]model.FileResult{}, flagged...)
		rows = append(rows, cleanRows(sum)...)
		for _, r := range rows {
			writeHTMLRow(&b, r)
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString(`</main>
<footer>CrackSentinel &middot; defensive scanner &middot; read the report, do not run the samples</footer>
<script>
(function(){
 var tb=document.getElementById('tbl'); if(!tb) return;
 var rows=Array.prototype.slice.call(tb.querySelectorAll('tbody tr'));
 var btns=Array.prototype.slice.call(document.querySelectorAll('.bar button'));
 var q=document.getElementById('q'), cnt=document.getElementById('cnt');
 var mode='all';
 function apply(){
  var term=(q.value||'').toLowerCase(), n=0;
  rows.forEach(function(r){
   var show = mode==='all' || r.dataset.v===mode;
   if(show && term){ show = (r.textContent||'').toLowerCase().indexOf(term)>=0; }
   r.classList.toggle('hide',!show); if(show) n++;
  });
  cnt.textContent=n+' shown';
 }
 btns.forEach(function(b){ b.addEventListener('click',function(){
   btns.forEach(function(x){x.classList.remove('on')}); b.classList.add('on');
   mode=b.dataset.f; apply();
 })});
 q.addEventListener('input',apply);
 tb.querySelectorAll('th').forEach(function(th){
  th.addEventListener('click',function(){
   var i=+th.dataset.s, asc=th.dataset.dir!=='asc';
   th.dataset.dir=asc?'asc':'desc';
   var body=tb.querySelector('tbody');
   var list=Array.prototype.slice.call(body.querySelectorAll('tr'));
   list.sort(function(a,b){
    var x=a.children[i].textContent.trim(), y=b.children[i].textContent.trim();
    var nx=parseFloat(x), ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny)) return asc?nx-ny:ny-nx;
    return asc?x.localeCompare(y):y.localeCompare(x);
   });
   list.forEach(function(r){body.appendChild(r)});
  });
 });
 apply();
})();
</script>
</body></html>`)

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// cleanRows returns the clean files, sorted by path, for the table body.
func cleanRows(sum *model.Summary) []model.FileResult {
	var out []model.FileResult
	for _, r := range sum.Results {
		if r.Skipped || r.Verdict != model.VerdictClean {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func writeHTMLRow(b *strings.Builder, r model.FileResult) {
	cls := "cln"
	switch r.Verdict {
	case model.VerdictMalicious:
		cls = "mal"
	case model.VerdictSuspicious:
		cls = "sus"
	}
	short := r.SHA256
	if len(short) > 16 {
		short = short[:16]
	}
	fmt.Fprintf(b, "<tr class=\"row\" data-v=\"%s\">", strings.ToLower(r.Verdict.String()))
	fmt.Fprintf(b, "<td class=\"vd %s\">%s</td>", cls, r.Verdict)
	fmt.Fprintf(b, "<td><span class=\"sc %s\">%d</span></td>", cls, r.Score)
	fmt.Fprintf(b, "<td class=\"p\">%s</td>", html.EscapeString(r.Path))
	fmt.Fprintf(b, "<td>%s</td>", html.EscapeString(r.Type))
	fmt.Fprintf(b, "<td class=\"hash\">%s</td>", html.EscapeString(short))
	b.WriteString("<td>")
	if len(r.Findings) == 0 {
		b.WriteString("<span class=\"ct\">no findings</span>")
	} else {
		n := 0
		for _, f := range r.Findings {
			if f.Severity > 0 {
				n++
			}
		}
		fmt.Fprintf(b, "<details><summary>%d finding(s) &middot; %s</summary>",
			n, html.EscapeString(topRules(r)))
		for _, f := range r.Findings {
			sv := f.Severity
			scls := "cln"
			if sv >= 70 {
				scls = "mal"
			} else if sv > 0 {
				scls = "sus"
			}
			fmt.Fprintf(b, "<div class=\"finding\"><div class=\"sv %s\">%d</div><div><div class=\"rg\">%s</div><div class=\"ct\">%s</div></div><div class=\"dt\">%s</div></div>",
				scls, sv, html.EscapeString(f.Rule), html.EscapeString(f.Category), html.EscapeString(f.Detail))
		}
		if r.Imphash != "" {
			fmt.Fprintf(b, "<div class=\"finding\"><div class=\"sv cln\">0</div><div><div class=\"rg\">imphash</div><div class=\"ct\">pe</div></div><div class=\"dt\">%s (signed=%v, packer=%s)</div></div>",
				html.EscapeString(r.Imphash), r.Signed, html.EscapeString(r.Packer))
		}
		b.WriteString("</details>")
	}
	b.WriteString("</td></tr>")
}

func topRules(r model.FileResult) string {
	if len(r.Findings) == 0 {
		return "-"
	}
	var parts []string
	for _, f := range r.Findings {
		if f.Severity <= 0 {
			continue
		}
		parts = append(parts, f.Rule)
		if len(parts) == 4 {
			break
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
