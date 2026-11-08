import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// A fresh database and signing key per run; never use a developer's live instance.
const directory = mkdtempSync(join(tmpdir(), 'zhuwei-console-e2e-'))
const env = { ...process.env, GOCACHE: process.env.GOCACHE || join(tmpdir(), 'zhuwei-go-cache'), RASP_ADMIN_PASSWORD: 'console-e2e-password' }
const binary = join(directory, 'rasp-server')
const build = spawnSync('go', ['build', '-o', binary, './cmd/rasp-server'], { cwd: '..', env, stdio: 'inherit' })
if (build.status !== 0) { rmSync(directory, { recursive: true, force: true }); process.exit(1) }
const port = process.env.RASP_E2E_PORT || '18480'
const server = spawn(binary, ['-listen', `127.0.0.1:${port}`, '-db', join(directory, 'test.db'), '-agent-url', `http://127.0.0.1:${port}`], { env, stdio: 'inherit' })
let stopping = false
function stop() { if (!stopping) { stopping = true; server.kill('SIGTERM') } }
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
server.on('exit', code => { rmSync(directory, { recursive: true, force: true }); process.exit(code || 0) })
