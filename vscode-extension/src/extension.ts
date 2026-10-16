// depscan for VS Code: a thin, read-only client over the depscan command line.
//
// It never edits dependency files and never installs anything. It runs `python -m depscan scan` on the folders that hold
// dependency files, shows what comes back in the Problems panel, a tree view and a details page, and records review
// decisions through `python -m depscan review` (which writes only depscan's own review database).
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import * as vscode from 'vscode'
import {
  type DiagSeverity, type Finding, type ScanResult,
  ACTION_LABEL, DISCLAIMER, cliError, detailsMarkdown, diagnosticMessage, expiryDefault, findLine, groupFindings,
  severityFor, sortByPriority, summaryLine,
} from './core'

const KNOWN = ['requirements.txt', 'package.json', 'package-lock.json', 'yarn.lock', 'poetry.lock', 'Pipfile.lock', 'go.mod']
const EXCLUDE = '**/{node_modules,.venv,venv,.git,dist,build,site-packages,__pycache__,out}/**'

interface Entry { finding: Finding; dir: string; resultFile: string; project: string }

let ctx: vscode.ExtensionContext
let entries: Entry[] = []
let warnings: string[] = []
let scanning = false
let lastScanAt: string | null = null
const output = vscode.window.createOutputChannel('depscan')
const diagnostics = vscode.languages.createDiagnosticCollection('depscan')
let statusBar: vscode.StatusBarItem
let treeView: vscode.TreeView<Node>
const treeChanged = new vscode.EventEmitter<Node | undefined>()

// ------------------------------------------------------------------ settings
function cfg<T>(key: string): T {
  return vscode.workspace.getConfiguration('depscan').get(key) as T
}

function repoPath(): string | undefined {
  const candidates = [cfg<string>('repoPath'), path.resolve(ctx.extensionPath, '..')].filter(Boolean)
  return candidates.find((p) => fs.existsSync(path.join(p, 'depscan', '__main__.py')))
}

function pythonPath(repo: string): string {
  const set = cfg<string>('pythonPath')
  if (set) return set
  const venv = process.platform === 'win32' ? path.join(repo, '.venv', 'Scripts', 'python.exe') : path.join(repo, '.venv', 'bin', 'python')
  return fs.existsSync(venv) ? venv : 'python'
}

// ------------------------------------------------------------------ running the CLI
function run(python: string, repo: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    output.appendLine(`> ${python} ${args.join(' ')}`)
    const child = spawn(python, args, { cwd: repo, windowsHide: true })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => (stdout += d))
    child.stderr.on('data', (d) => (stderr += d))
    child.on('error', (e) => resolve({ code: -1, stdout, stderr: `error: could not start ${python}: ${e.message}` }))
    child.on('close', (code) => resolve({ code, stdout, stderr }))
  })
}

// ------------------------------------------------------------------ finding the projects to scan
async function targets(): Promise<{ dir: string; project: string }[]> {
  const glob = `**/{${KNOWN.join(',')}}`
  const found = await vscode.workspace.findFiles(glob, EXCLUDE, 300)
  const dirs = new Map<string, string>()
  for (const uri of found) {
    const dir = path.dirname(uri.fsPath)
    const folder = vscode.workspace.getWorkspaceFolder(uri)
    const rel = folder ? path.relative(folder.uri.fsPath, dir) : ''
    dirs.set(dir, [folder?.name ?? path.basename(dir), rel].filter(Boolean).join('/').replace(/\\/g, '/'))
  }
  return [...dirs].map(([dir, project]) => ({ dir, project }))
}

// ------------------------------------------------------------------ scanning
async function scan(): Promise<void> {
  if (scanning) return
  const repo = repoPath()
  if (!repo) {
    vscode.window.showErrorMessage('depscan: cannot find the depscan project. Set "depscan.repoPath" to the folder that contains the depscan package.')
    return
  }
  const python = pythonPath(repo)
  scanning = true
  setStatus('$(sync~spin) depscan: scanning')
  try {
    const found = await targets()
    if (found.length === 0) {
      vscode.window.showInformationMessage('depscan: no dependency files (requirements.txt, package.json, lock files, go.mod) in this workspace.')
      entries = []
      warnings = []
      return
    }
    const store = ctx.globalStorageUri.fsPath
    fs.mkdirSync(store, { recursive: true })
    const all: Entry[] = []
    const allWarnings: string[] = []
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'depscan: scanning dependencies', cancellable: false }, async (progress) => {
      let i = 0
      for (const t of found) {
        progress.report({ message: `${t.project || t.dir} (${++i}/${found.length})` })
        const resultFile = path.join(store, `result-${createHash('sha1').update(t.dir).digest('hex').slice(0, 16)}.json`)   // one file per folder, never shared
        const args = ['-m', 'depscan', 'scan', t.dir, '--out', resultFile, `--project=${t.project || 'default'}`]
        if (cfg<boolean>('offline')) args.push('--offline')
        const dataDir = cfg<string>('dataDir')
        if (dataDir) args.push('--data-dir', dataDir)
        const r = await run(python, repo, args)
        if (r.code !== 0) {
          output.appendLine(r.stderr)
          vscode.window.showErrorMessage(`depscan: ${cliError(r.stderr, r.code)}`)
          continue
        }
        const result = JSON.parse(fs.readFileSync(resultFile, 'utf8')) as ScanResult
        lastScanAt = result.scanned_at
        allWarnings.push(...(result.warnings ?? []))
        for (const finding of result.findings) all.push({ finding, dir: t.dir, resultFile, project: t.project || 'default' })
      }
    })
    entries = all
    warnings = allWarnings
    await publishDiagnostics()
  } catch (e) {
    vscode.window.showErrorMessage(`depscan: ${e instanceof Error ? e.message : String(e)}`)
  } finally {
    scanning = false
    refreshViews()
  }
}

// ------------------------------------------------------------------ Problems panel
const SEVERITY: Record<DiagSeverity, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
}

async function publishDiagnostics(): Promise<void> {
  diagnostics.clear()
  const byFile = new Map<string, vscode.Diagnostic[]>()
  const texts = new Map<string, string>()
  const dirs = [...new Set(entries.map((e) => e.dir))]
  const candidates = new Map(dirs.map((d) => [d, sortByPriority(KNOWN.filter((n) => fs.existsSync(path.join(d, n))).concat(fs.existsSync(path.join(d, 'Pipfile')) ? ['Pipfile'] : []))]))
  for (const { finding: f, dir } of entries) {
    let target: { file: string; line: number } | null = null
    for (const name of candidates.get(dir) ?? []) {
      const file = path.join(dir, name)
      if (!texts.has(file)) texts.set(file, fs.readFileSync(file, 'utf8'))
      const line = findLine(texts.get(file) as string, name, f.package)
      if (line !== null) { target = { file, line }; break }
    }
    const first = candidates.get(dir)?.[0]
    if (!target && first) target = { file: path.join(dir, first), line: 0 }
    if (!target) continue
    const text = (texts.get(target.file) ?? '').split(/\r?\n/)[target.line] ?? ''
    const range = new vscode.Range(target.line, 0, target.line, Math.max(text.length, 1))
    const d = new vscode.Diagnostic(range, diagnosticMessage(f), SEVERITY[severityFor(f)])
    d.source = 'depscan'
    d.code = { value: f.id, target: vscode.Uri.parse(`https://osv.dev/vulnerability/${encodeURIComponent(f.id)}`) }
    byFile.set(target.file, [...(byFile.get(target.file) ?? []), d])
  }
  for (const [file, list] of byFile) diagnostics.set(vscode.Uri.file(file), list)
}

// ------------------------------------------------------------------ tree view
type Node = GroupNode | FindingNode

class GroupNode extends vscode.TreeItem {
  constructor(public readonly group: ReturnType<typeof groupFindings>[number]) {
    super(`${group.label} (${group.findings.length})`, group.action === 'fix_now' ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed)
    this.contextValue = 'group'
  }
}

class FindingNode extends vscode.TreeItem {
  constructor(public readonly entry: Entry) {
    const f = entry.finding
    super(`${f.package} ${f.version}`, vscode.TreeItemCollapsibleState.None)
    this.description = `${f.id}  risk ${f.risk.score.toFixed(0)} · trust ${f.trust.score.toFixed(0)}${f.review_status !== 'pending' ? ` · ${f.review_status.replace('_', ' ')}` : ''}`
    this.tooltip = new vscode.MarkdownString(`**${f.id}** in ${f.package} ${f.version}\n\n${f.summary}\n\n${ACTION_LABEL[f.action]}. ${f.recommendation}`)
    const color = { fix_now: 'errorForeground', verify_first: 'editorWarning.foreground', monitor: 'editorInfo.foreground', no_action: 'disabledForeground' }[f.action]
    this.iconPath = new vscode.ThemeIcon(f.kev ? 'flame' : 'shield', new vscode.ThemeColor(color))
    this.contextValue = 'finding'
    this.command = { command: 'depscan.showFinding', title: 'Show finding details', arguments: [this] }
  }
}

const provider: vscode.TreeDataProvider<Node> = {
  onDidChangeTreeData: treeChanged.event,
  getTreeItem: (n) => n,
  getChildren: (n) => {
    if (!n) return groupFindings(entries.map((e) => e.finding)).map((g) => new GroupNode(g))
    if (n instanceof GroupNode) return n.group.findings.map((f) => new FindingNode(entries.find((e) => e.finding === f) as Entry))
    return []
  },
}

function setStatus(text: string): void {
  statusBar.text = text
  statusBar.show()
}

function refreshViews(): void {
  treeChanged.fire(undefined)
  const findings = entries.map((e) => e.finding)
  setStatus(`$(shield) ${summaryLine(findings)}`)
  statusBar.tooltip = `${lastScanAt ? `Last scan ${lastScanAt}. ` : ''}${DISCLAIMER}\nClick to scan again.`
  const warn = warnings.length ? ` ${warnings.length} warning(s): see the depscan output.` : ''
  treeView.message = entries.length || lastScanAt ? `${DISCLAIMER}${warn}` : undefined
  if (warnings.length) for (const w of warnings) output.appendLine(`warning: ${w}`)
}

// ------------------------------------------------------------------ commands
async function pickEntry(node?: Node): Promise<Entry | undefined> {
  if (node instanceof FindingNode) return node.entry
  if (entries.length === 0) {
    vscode.window.showInformationMessage('depscan: scan the workspace first.')
    return undefined
  }
  const pick = await vscode.window.showQuickPick(
    entries.map((e) => ({ label: `${e.finding.package} ${e.finding.version}`, description: e.finding.id, detail: `risk ${e.finding.risk.score.toFixed(0)}: ${ACTION_LABEL[e.finding.action]}`, e })),
    { placeHolder: 'Choose a finding' },
  )
  return pick?.e
}

async function showFinding(node?: Node): Promise<void> {
  const entry = await pickEntry(node)
  if (!entry) return
  const store = ctx.globalStorageUri.fsPath
  fs.mkdirSync(store, { recursive: true })
  const file = path.join(store, 'finding.md')
  fs.writeFileSync(file, detailsMarkdown(entry.finding), 'utf8')
  await vscode.commands.executeCommand('markdown.showPreview', vscode.Uri.file(file))
}

async function reviewFinding(node?: Node): Promise<void> {
  const entry = await pickEntry(node)
  if (!entry) return
  const f = entry.finding
  const decided = f.review_status !== 'pending'
  const options = [
    { label: 'Fix now', description: 'we are scheduling the upgrade', id: 'fix_now' },
    { label: 'Accept risk', description: 'needs an expiry date', id: 'accept_risk' },
    { label: 'False positive', description: 'needs an expiry date', id: 'false_positive' },
    ...(decided ? [{ label: 'Revoke the current decision', description: 'needs review again', id: 'revoke' }] : []),
  ]
  const choice = await vscode.window.showQuickPick(options, { placeHolder: `${f.package} ${f.version} ${f.id}: your decision (recorded in the audit log)` })
  if (!choice) return
  const note = await vscode.window.showInputBox({
    prompt: 'The reason (at least 10 characters). It is kept in the audit log.',
    validateInput: (v) => (v.trim().length < 10 ? 'Give a real reason, at least 10 characters' : undefined),
  })
  if (note === undefined) return
  let reviewer = cfg<string>('reviewer').trim()
  if (!reviewer) {
    reviewer = (await vscode.window.showInputBox({ prompt: 'Your name (typed in, not authenticated)', value: os.userInfo().username })) ?? ''
    if (!reviewer.trim()) return
    await vscode.workspace.getConfiguration('depscan').update('reviewer', reviewer.trim(), vscode.ConfigurationTarget.Global)
  }
  const args = ['-m', 'depscan', 'review', entry.resultFile, f.key, choice.id, `--reviewer=${reviewer}`, `--note=${note}`, `--project=${entry.project}`]
  if (choice.id === 'accept_risk' || choice.id === 'false_positive') {
    const expires = await vscode.window.showInputBox({
      prompt: 'Expires on (YYYY-MM-DD). Critical-tier findings: at most 30 days; others: at most 180.',
      value: expiryDefault(f, new Date()),
      validateInput: (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v) ? undefined : 'Use YYYY-MM-DD'),
    })
    if (!expires) return
    args.push(`--expires=${expires}`)
  }
  const repo = repoPath()
  if (!repo) return
  const r = await run(pythonPath(repo), repo, args)
  if (r.code !== 0) {
    vscode.window.showErrorMessage(`depscan: ${cliError(r.stderr, r.code)}`)
    return
  }
  vscode.window.showInformationMessage(`depscan: ${r.stdout.trim()}`)
  await scan()                                   // re-read so the tree and the Problems panel show the stored decision
}

async function showAudit(): Promise<void> {
  const repo = repoPath()
  if (!repo) return
  const r = await run(pythonPath(repo), repo, ['-m', 'depscan', 'audit', '--limit', '50'])
  output.show(true)
  output.appendLine(r.code === 0 ? `--- audit log (newest first) ---\n${r.stdout}` : `error: ${cliError(r.stderr, r.code)}`)
}

async function openConsole(): Promise<void> {
  const url = cfg<string>('consoleUrl')
  let up = false
  try {
    up = (await fetch(new URL('/api/health', url), { signal: AbortSignal.timeout(1500) })).ok
  } catch {
    up = false
  }
  if (!up) {
    const repo = repoPath()
    const pick = await vscode.window.showInformationMessage('The depscan web console is not running.', 'Start it in a terminal', 'Open anyway')
    if (pick === 'Start it in a terminal' && repo) {
      // run python directly (no shell), so it works the same in PowerShell, cmd and bash
      const term = vscode.window.createTerminal({
        name: 'depscan console', cwd: repo, shellPath: pythonPath(repo),
        shellArgs: ['-m', 'depscan', 'serve', ...(cfg<boolean>('offline') ? ['--offline'] : [])],
      })
      term.show()
      await new Promise((r) => setTimeout(r, 2500))
    } else if (pick !== 'Open anyway') {
      return
    }
  }
  await vscode.env.openExternal(vscode.Uri.parse(url))
}

function clear(): void {
  entries = []
  warnings = []
  lastScanAt = null
  diagnostics.clear()
  refreshViews()
}

// ------------------------------------------------------------------ lifecycle
export function activate(context: vscode.ExtensionContext): void {
  ctx = context
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50)
  statusBar.command = 'depscan.scan'
  statusBar.text = '$(shield) depscan'
  statusBar.tooltip = `Click to scan this workspace. ${DISCLAIMER}`
  statusBar.show()
  treeView = vscode.window.createTreeView('depscan.findings', { treeDataProvider: provider })
  let timer: NodeJS.Timeout | undefined
  context.subscriptions.push(
    output, diagnostics, statusBar, treeView, treeChanged,
    vscode.commands.registerCommand('depscan.scan', scan),
    vscode.commands.registerCommand('depscan.showFinding', showFinding),
    vscode.commands.registerCommand('depscan.reviewFinding', reviewFinding),
    vscode.commands.registerCommand('depscan.showAudit', showAudit),
    vscode.commands.registerCommand('depscan.openConsole', openConsole),
    vscode.commands.registerCommand('depscan.clear', clear),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!cfg<boolean>('scanOnSave') || !KNOWN.includes(path.basename(doc.fileName))) return
      clearTimeout(timer)
      timer = setTimeout(() => void scan(), 1000)
    }),
  )
}

export function deactivate(): void {
  // nothing to clean up: scan results live in the extension's own storage folder
}
