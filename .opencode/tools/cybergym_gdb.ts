import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Run a batch gdb session inside a dynamic-whole container to inspect memory details directly. Uses a static gdb mounted at /opt/gdb (gdb-13 preferred, gdb-8.3 fallback) — works in every task image without installing anything. Requires an active cybergym_dyn_start session. The gdb script is written to /work/gdbcmds.txt and run with `gdb -batch -x ... --args <program> <args>`. Non-interactive settings and sanitizer env are auto-set (ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 so `bt` shows the real crash call chain; UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1). By default a crash snapshot is appended: run -> bt 40 / info registers / x/24gx $rsp / info frame. If your `script` already contains a `run`/`start` command, the auto snapshot is skipped and you control stepping. Use `script` for breakpoints (b file.c:LINE, rbreak ^fn$), conditions, printf logging, and memory inspection (x/s, x/8gx $rdi). Then run again with a modified script to iterate — the container and any files in /work persist between calls. Only debug the VULNERABLE side; never inspect fix artifacts.",
  args: {
    session_id: tool.schema.string().describe("Session id returned by cybergym_dyn_start"),
    program: tool.schema.string().describe("Path to the target binary inside the container, e.g. /out/wpantund-fuzz or /out/ffmpeg_AV_CODEC_ID_AAC_fuzzer"),
    args: tool.schema.string().optional().describe("Target arguments passed after --args, e.g. /work/inputs/poc.bin or -max_total_time=60 /work/corpus. Safe chars only: alnum . / - _ : = , @ % space"),
    script: tool.schema.string().optional().describe("gdb commands as a multiline string: breakpoints, conditions, printf, x/ memory, bt. If it contains a run/start command, the auto crash snapshot is skipped"),
    gdb_version: tool.schema.string().optional().describe("auto | 13 | 8 (default auto: prefer gdb-13)"),
    timeout: tool.schema.number().optional().describe("Seconds, max 600 (default 120). Large debug symbols load slowly — raise if it times out"),
    snapshot: tool.schema.boolean().optional().describe("Append crash snapshot (bt/info registers/x/\\$rsp). Default true; set false to suppress"),
    purpose: tool.schema.string().optional().describe("Why you are running gdb"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: [
        "python3", "opencode_bridge.py", "gdb",
        args.session_id,
        "--program", args.program,
        ...(args.args ? ["--args", args.args] : []),
        ...(args.script ? ["--script", args.script] : []),
        ...(args.gdb_version ? ["--gdb-version", args.gdb_version] : []),
        ...(args.timeout ? ["--timeout", String(args.timeout)] : []),
        ...(args.snapshot === false ? ["--no-snapshot"] : []),
        ...(args.purpose ? ["--purpose", args.purpose] : []),
      ],
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
