import { tool } from "@opencode-ai/plugin"

export default tool({
  description:
    "Search the shared experience knowledge base (knowledge/format + knowledge/reasoning) for entries relevant to the current task. Pass task-relevant technical terms: format names, library names, parser mechanisms, sanitizer/tool behaviors (e.g. 'tiff rawtile', 'wireshark cotp', 'swift inline asan', 'fuzzed data provider'). Returns ranked entry titles + summaries (advisory hints). Entries with source_outcome='fail' are PROVISIONAL — they came from an unsolved task and may encode a wrong hypothesis; verify against this task before adopting. Use this early, after reading the task description/source, to quickly locate prior knowledge instead of grepping raw JSONL.",
  args: {
    query: tool.schema.string().describe("Space-separated technical terms to search (format/library/mechanism/behavior)"),
    domain: tool.schema.string().optional().describe("Restrict search to 'format' or 'reasoning'"),
    limit: tool.schema.number().optional().describe("Max results to return (default 5)"),
  },
  async execute(args) {
    const cmd = [
      "python3", "opencode_bridge.py", "knowledge_search", args.query,
      ...(args.domain ? ["--domain", args.domain] : []),
      ...(args.limit ? ["--limit", String(args.limit)] : []),
    ]
    const proc = Bun.spawnSync({
      cmd,
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
