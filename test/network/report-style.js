// Styles for report.html, inlined into the page by report.js.
export const reportCss = `
.viz-root {
  color-scheme: light;
  --page: #f9f9f7;
  --surface-1: #fcfcfb;
  --text-primary: #0b0b0b;
  --text-secondary: #52514e;
  --muted: #898781;
  --grid: #e1e0d9;
  --axis: #c3c2b7;
  --border: rgba(11, 11, 11, 0.1);
  --wash: rgba(11, 11, 11, 0.04);
  --series-1: #2a78d6;
  --series-2: #eb6834;
  --series-3: #1baf7a;
  --good: #0ca30c;
  --good-text: #006300;
  --critical: #d03b3b;
  --warning: #fab219;
  --hatch: rgba(11, 11, 11, 0.16);
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme='light'])) .viz-root {
    color-scheme: dark;
    --page: #0d0d0d;
    --surface-1: #1a1a19;
    --text-primary: #f0efec;
    --text-secondary: #c3c2b7;
    --grid: #2c2c2a;
    --axis: #383835;
    --border: rgba(255, 255, 255, 0.1);
    --wash: rgba(255, 255, 255, 0.05);
    --series-1: #3987e5;
    --series-2: #d95926;
    --series-3: #199e70;
    --good-text: #0ca30c;
    --hatch: rgba(255, 255, 255, 0.18);
  }
}
:root[data-theme='dark'] .viz-root {
  color-scheme: dark;
  --page: #0d0d0d;
  --surface-1: #1a1a19;
  --text-primary: #f0efec;
  --text-secondary: #c3c2b7;
  --grid: #2c2c2a;
  --axis: #383835;
  --border: rgba(255, 255, 255, 0.1);
  --wash: rgba(255, 255, 255, 0.05);
  --series-1: #3987e5;
  --series-2: #d95926;
  --series-3: #199e70;
  --good-text: #0ca30c;
  --hatch: rgba(255, 255, 255, 0.18);
}

* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--page);
  color: var(--text-primary);
  font: 14px/1.45 system-ui, -apple-system, 'Segoe UI', sans-serif;
}
main {
  max-width: 1280px;
  margin: 0 auto;
  padding: 24px 24px 64px;
}
h1 {
  font-size: 20px;
  margin: 0 0 4px;
  font-weight: 600;
}
h2 {
  font-size: 15px;
  margin: 0 0 4px;
  font-weight: 600;
}
.sub {
  color: var(--text-secondary);
  font-size: 13px;
}
.muted {
  color: var(--muted);
}
code,
pre,
.mono {
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-size: 12px;
}

header.top {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 16px;
}
.status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 13px;
  border: 1px solid currentColor;
}
.status.fail {
  color: var(--critical);
}
.status.ok {
  color: var(--good-text);
}
.failure {
  border-left: 3px solid var(--critical);
  background: var(--surface-1);
  padding: 8px 12px;
  margin: 0 0 16px;
  border-radius: 0 6px 6px 0;
  white-space: pre-wrap;
}
button {
  font: inherit;
  font-size: 13px;
  color: var(--text-primary);
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 3px 10px;
  cursor: pointer;
}
button:hover {
  background: var(--wash);
}
button[aria-pressed='false'] {
  color: var(--muted);
}

.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.tile {
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
}
.tile .k {
  color: var(--text-secondary);
  font-size: 12px;
}
.tile .v {
  font-size: 22px;
  font-weight: 600;
}
.tile .d {
  color: var(--text-secondary);
  font-size: 12px;
}

section.card {
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  margin-bottom: 16px;
}
.card-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.legend {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--text-secondary);
  align-items: center;
}
.legend .sw {
  display: inline-block;
  width: 14px;
  height: 8px;
  border-radius: 2px;
  vertical-align: middle;
  margin-right: 5px;
}
.legend .sw.line {
  height: 2px;
}
.legend .sw.hatch {
  background: repeating-linear-gradient(45deg, var(--hatch) 0 2px, transparent 2px 5px);
  border: 1px solid var(--axis);
}
.legend .sw.hatch.crit {
  background: repeating-linear-gradient(45deg, var(--critical) 0 1.5px, transparent 1.5px 5px);
  border-color: var(--critical);
  opacity: 0.6;
}
.legend .glyph {
  font-weight: 700;
  margin-right: 4px;
}

svg {
  display: block;
  overflow: visible;
}
svg text {
  fill: var(--text-secondary);
  font-size: 11px;
}
svg .ink {
  fill: var(--text-primary);
}
svg .muted-ink {
  fill: var(--muted);
}
svg .grid {
  stroke: var(--grid);
  stroke-width: 1;
}
svg .axis {
  stroke: var(--axis);
  stroke-width: 1;
}
.diagram-wrap {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 260px;
  gap: 16px;
}
@media (max-width: 900px) {
  .diagram-wrap {
    grid-template-columns: 1fr;
  }
}
.side {
  font-size: 13px;
  border-left: 1px solid var(--grid);
  padding-left: 14px;
}
.side dt {
  color: var(--text-secondary);
  font-size: 12px;
  margin-top: 8px;
}
.side dd {
  margin: 0;
}
.cursor-read {
  font-variant-numeric: tabular-nums;
}

.toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 8px;
  font-size: 13px;
}
.toolbar input[type='search'],
.toolbar select {
  font: inherit;
  font-size: 13px;
  color: var(--text-primary);
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 3px 8px;
}
.toolbar input[type='search'] {
  min-width: 220px;
}
.toolbar .spacer {
  flex: 1;
}

.table-wrap {
  max-height: 520px;
  overflow: auto;
  border: 1px solid var(--grid);
  border-radius: 6px;
}
table {
  border-collapse: collapse;
  width: 100%;
  font-size: 12px;
}
th {
  position: sticky;
  top: 0;
  background: var(--surface-1);
  text-align: left;
  font-weight: 600;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--axis);
  padding: 4px 8px;
}
td {
  padding: 3px 8px;
  border-bottom: 1px solid var(--grid);
  vertical-align: top;
}
td.num {
  font-variant-numeric: tabular-nums;
  text-align: right;
  white-space: nowrap;
}
td.fields {
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-size: 11px;
  color: var(--text-secondary);
  word-break: break-all;
}
tr.row {
  cursor: pointer;
}
tr.row:hover td {
  background: var(--wash);
}
tr.row.pinned td {
  background: var(--wash);
  box-shadow: inset 2px 0 0 var(--series-1);
}
tr.row.err td:nth-child(3) {
  color: var(--critical);
  font-weight: 600;
}

.steps-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
}
ol.plan {
  margin: 4px 0 0;
  padding-left: 0;
  list-style: none;
  font-size: 12px;
}
ol.plan li {
  padding: 1px 0 1px 22px;
  position: relative;
}
ol.plan li::before {
  position: absolute;
  left: 0;
  width: 18px;
  text-align: center;
  font-weight: 700;
}
ol.plan li.done::before {
  content: '✓';
  color: var(--good-text);
}
ol.plan li.current::before {
  content: '▶';
  color: var(--critical);
}
ol.plan li.current {
  font-weight: 600;
}
ol.plan li.todo {
  color: var(--muted);
}
ol.plan li.todo::before {
  content: '·';
}

details {
  margin-top: 8px;
}
details summary {
  cursor: pointer;
  color: var(--text-secondary);
}
details pre {
  background: var(--page);
  border: 1px solid var(--grid);
  border-radius: 6px;
  padding: 8px 10px;
  overflow: auto;
  max-height: 360px;
}

#tip {
  position: fixed;
  z-index: 10;
  pointer-events: none;
  max-width: 420px;
  background: var(--surface-1);
  color: var(--text-primary);
  border: 1px solid var(--border);
  border-radius: 6px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.16);
  padding: 6px 9px;
  font-size: 12px;
}
#tip .tt {
  font-weight: 600;
  margin-bottom: 2px;
}
#tip .kv {
  color: var(--text-secondary);
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-size: 11px;
  word-break: break-all;
}
@media (forced-colors: active) {
  .status,
  .failure {
    border-color: CanvasText;
  }
}
`
