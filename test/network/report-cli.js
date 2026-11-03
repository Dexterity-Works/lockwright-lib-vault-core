// Render a run as report.html:
//   node test/network/report-cli.js <timeline.json | artifact dir | lab run dir> [out.html]
import { writeReport } from './report.js'

const [input, out] = process.argv.slice(2)
if (!input) {
  // eslint-disable-next-line no-console
  console.error(
    'usage: report-cli.js <timeline.json | artifact dir | lab run dir> [out.html]'
  )
  process.exit(2)
}
// eslint-disable-next-line no-console
console.log(`report: ${writeReport(input, out)}`)
