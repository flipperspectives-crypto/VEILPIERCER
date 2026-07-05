#!/usr/bin/env python3
"""
VeilPiercer Agent Logger — Live Auto-Logging for Hermes/Lucy
=============================================================
Drop-in adapter that logs every agent action to a VeilPiercer v2.1
chained Merkle ledger. Use from cron, slash commands, or import.

Modes:
  python3 vp_agent_logger.py log <ledger.json> <action_type> '<json>'
  python3 vp_agent_logger.py flush <ledger.json> [--ots]
  python3 vp_agent_logger.py status <ledger.json>
  python3 vp_agent_logger.py tail <ledger.json> [N]

Python API:
  from vp_agent_logger import AgentLogger
  al = AgentLogger("audit.json")
  al.log_decision("check disk space", model="deepseek-v4-pro")
  al.log_tool_call("terminal", "df -h")
  al.log_result(0, "/data 45% used")
  al.flush()  # builds Merkle tree, returns root
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from veil_piercer import VeilPiercer


class AgentLogger:
    """High-level logger for Hermes agent actions."""

    def __init__(self, ledger_path: str):
        self.path = ledger_path
        self.vp = VeilPiercer()
        if os.path.exists(ledger_path):
            self.vp.load(ledger_path)

    def log_decision(self, prompt: str, **kwargs) -> dict:
        """Log a Hermes decision/planning step."""
        return self.vp.log_action("HERMES_DECISION", {
            "prompt": prompt[:200],
            "model": kwargs.get("model", "unknown"),
            "tools_available": kwargs.get("tools", []),
        })

    def log_tool_call(self, tool: str, command: str, args: dict = None) -> dict:
        """Log a tool invocation."""
        return self.vp.log_action("TOOL_CALL", {
            "tool": tool,
            "command": str(command)[:500],
            "args": args or {},
        })

    def log_result(self, exit_code: int, output: str, tool: str = "unknown") -> dict:
        """Log a tool execution result."""
        return self.vp.log_action("RESULT", {
            "tool": tool,
            "exit_code": exit_code,
            "output_preview": str(output)[:500],
        })

    def log_error(self, error: str, context: str = "") -> dict:
        """Log an error/failure."""
        return self.vp.log_action("ERROR", {
            "error": str(error)[:500],
            "context": context[:200],
        })

    def log_generic(self, action_type: str, data: dict) -> dict:
        """Log any action type with arbitrary data."""
        return self.vp.log_action(action_type, data)

    def flush(self, anchor_ots: bool = False) -> str:
        """Flush current batch → Merkle root. Save + optional OTS anchor."""
        root = self.vp.flush_batch()
        if anchor_ots:
            bi = len(self.vp.batch_chain) - 1
            ots_data = json.dumps({
                "batch_index": bi, "root": root,
                "entries": self.vp.batch_chain[bi]["entry_count"],
                "flushed": self.vp.batch_chain[bi]["flushed_utc"],
            })
            proof_dir = os.path.dirname(os.path.abspath(self.path)) or "."
            self.vp.anchor_ots(bi, ots_data, proof_dir)
        self.vp.save(self.path)
        return root

    def status(self) -> dict:
        """Get current logger status."""
        chain = self.vp.verify_chain()
        ots = self.vp.ots_status()
        summary = self.vp.chain_summary()
        return {
            "path": self.path,
            "chain_valid": chain["valid"],
            "total_entries": summary["total_entries"],
            "batch_count": summary["batch_count"],
            "pending_entries": self.vp.entry_count() - self.vp.batch_start,
            "latest_root": summary["latest_root"][:32] if summary["latest_root"] else None,
            "chain_id": summary["chain_id"][:16],
            "ots": {"anchored": ots["anchored"], "pending": ots["pending"]},
            "batches": summary["batches"],
            "failures": chain["failures"],
        }

    def tail(self, n: int = 10) -> list:
        """Return last N entries."""
        return self.vp.ledger[-n:]

    def save(self):
        """Persist to disk."""
        self.vp.save(self.path)


# ── CLI ────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    cmd, path = sys.argv[1], sys.argv[2]
    al = AgentLogger(path)

    if cmd == "log":
        if len(sys.argv) < 5:
            print("Usage: vp_agent_logger.py log <ledger.json> <type> '<json>'")
            return 1
        entry = al.log_generic(sys.argv[3], json.loads(sys.argv[4]))
        al.save()
        print(f"[{entry['index']}] {entry['action']} {entry['hash'][:12]}...")

    elif cmd == "flush":
        anchor = "--ots" in sys.argv
        root = al.flush(anchor_ots=anchor)
        bi = len(al.vp.batch_chain) - 1
        print(f"Batch {bi}: {al.vp.batch_chain[bi]['entry_count']} entries")
        print(f"Root: {root}")
        if anchor:
            print(f"OTS: {al.vp.batch_chain[bi].get('ots_proof_path', 'N/A')}")

    elif cmd == "status":
        st = al.status()
        print(f"Ledger:    {st['path']}")
        print(f"Chain:     {'VALID' if st['chain_valid'] else 'BROKEN'}")
        print(f"Entries:   {st['total_entries']} total, {st['pending_entries']} pending")
        print(f"Batches:   {st['batch_count']}")
        print(f"Root:      {st['latest_root']}")
        print(f"Chain ID:  {st['chain_id']}")
        print(f"OTS:       {st['ots']['anchored']} anchored, {st['ots']['pending']} pending")
        if st["failures"]:
            print(f"Failures:  {len(st['failures'])}")
        for b in st["batches"]:
            print(f"  [{b['index']}] {b['root']} ({b['entries']} entries) {b['flushed']}")

    elif cmd == "tail":
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        for e in al.tail(n):
            print(f"[{e['index']}] {e['timestamp_utc']} {e['action']} {json.dumps(e['metadata'])[:80]}")

    else:
        print(f"Unknown: {cmd}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())