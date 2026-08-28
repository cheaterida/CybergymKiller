import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Run a command inside a dynamic-whole session container. The container has full build toolchain (gcc/clang/cmake/make), the real source under /src, the target fuzzers under /out, and your inputs mounted read-only at /work/inputs. Container is offline (no network) and non-privileged; docker is not available inside. You may compile, run fuzzers, and debug. Prefix with timeout=N (max 600) to override the default 60s. Call cybergym_dyn_stop when finished.",
  args: {
    session_id: tool.schema.string().describe("Session id returned by cybergym_dyn_start"),
    command: tool.schema.string().describe("Shell command to run inside the container (executed as bash -c). Optionally prefix timeout=N to override the 60s default."),
    purpose: tool.schema.string().optional().describe("Why you are running this command"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: ["python3", "opencode_bridge.py", "dyn_exec", args.session_id, args.command, args.purpose ?? ""],
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    })
    const out = proc.stdout?.toString() ?? ""
    const err = proc.stderr?.toString() ?? ""
    if (proc.exitCode !== 0) {
      return `ERROR (exit ${proc.exitCode}): ${err || out}`
    }
    return out
  },
})
