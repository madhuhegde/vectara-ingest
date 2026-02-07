#!/usr/bin/env python3
"""
Identify unique email threads and group replies with originals from a PST text dump.
Uses Message-ID, In-Reply-To, and References headers; falls back to base subject.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def _parse_headers(header_text: str) -> dict:
    """Parse RFC-style headers (Name: value with continuation lines)."""
    headers = {}
    current_key = None
    current_val = []
    for line in header_text.splitlines():
        if line.startswith((" ", "\t")) and current_key is not None:
            current_val.append(line.strip())
            continue
        if ":" in line:
            if current_key is not None:
                headers[current_key.lower()] = " ".join(current_val)
            key, _, value = line.partition(":")
            current_key = key.strip().lower()
            current_val = [value.strip()]
    if current_key is not None:
        headers[current_key.lower()] = " ".join(current_val)
    return headers


def _extract_message_ids(value: str) -> list:
    """Extract Message-IDs from a header value (angle-bracket form). Returns list of ids."""
    if not value:
        return []
    ids = re.findall(r"<([^>]+)>", value)
    return [i.strip() for i in ids if "@" in i]


def _base_subject(subject: str) -> str:
    """Normalize subject for fallback threading: strip Re:/Fwd:/prefixes, lowercase."""
    if not subject:
        return ""
    s = subject.strip()
    while True:
        s2 = re.sub(r"^\s*Re:\s*", "", s, flags=re.IGNORECASE)
        s2 = re.sub(r"^\s*Fwd?:\s*", "", s2, flags=re.IGNORECASE)
        s2 = re.sub(r"^\s*\[[^\]]+\]\s*", "", s2)
        s2 = s2.strip()
        if s2 == s:
            break
        s = s2
    return " ".join(s.lower().split())


def main():
    parser = argparse.ArgumentParser(
        description="Identify unique email threads and group replies from a PST dump."
    )
    parser.add_argument(
        "dump_file",
        nargs="?",
        default=None,
        help="Path to pst_dump.txt (default: pst_dump.txt in project root)",
    )
    parser.add_argument(
        "-o", "--out",
        default=None,
        help="Write thread summary to JSON file",
    )
    parser.add_argument(
        "--by-subject",
        action="store_true",
        help="Also group by base subject (fallback when References missing)",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Print table as CSV: thread_root_id, subject, message_count",
    )
    args = parser.parse_args()

    dump_path = Path(args.dump_file) if args.dump_file else Path(__file__).resolve().parent.parent / "pst_dump.txt"
    if not dump_path.exists():
        print(f"Error: file not found: {dump_path}", file=sys.stderr)
        sys.exit(1)

    text = dump_path.read_text(encoding="utf-8", errors="replace")

    # Split into message blocks: "  [N] Subject: ..." ... until next "  [M] Subject:" or end
    block_pattern = re.compile(
        r"\n\s+\[(\d+)\]\s+Subject:\s*(.+?)(?=\n)"
        r"(.*?)(?=\n\s+\[\d+\]\s+Subject:|\Z)",
        re.DOTALL,
    )
    blocks = list(block_pattern.finditer(text))

    messages = []
    for m in blocks:
        msg_num = int(m.group(1))
        subject = m.group(2).strip()
        rest = m.group(3)
        # Extract Headers section (from "Date:" or "Headers:" until "Body:")
        date_match = re.search(r"Date:\s*([^\n]+)", rest)
        date_str = date_match.group(1).strip() if date_match else ""
        headers_match = re.search(r"Headers:\s*(.*?)(?=\n\s+Body:)", rest, re.DOTALL)
        header_text = headers_match.group(1).strip() if headers_match else ""
        headers = _parse_headers(header_text)

        message_id = headers.get("message-id", "").strip()
        mid_list = _extract_message_ids(message_id)
        this_mid = mid_list[0] if mid_list else f"__no_mid_{msg_num}"

        in_reply_to = headers.get("in-reply-to", "").strip()
        in_reply_to_ids = _extract_message_ids(in_reply_to)
        references = headers.get("references", "").strip()
        ref_ids = _extract_message_ids(references)

        # Thread root: first in References, else In-Reply-To, else this message's ID
        if ref_ids:
            thread_root_id = ref_ids[0]
        elif in_reply_to_ids:
            thread_root_id = in_reply_to_ids[0]
        else:
            thread_root_id = this_mid

        base_subj = _base_subject(subject)

        messages.append({
            "msg_num": msg_num,
            "subject": subject,
            "date": date_str,
            "message_id": this_mid,
            "in_reply_to": in_reply_to_ids[0] if in_reply_to_ids else None,
            "references": ref_ids,
            "thread_root_id": thread_root_id,
            "base_subject": base_subj,
        })

    # Group by thread root
    by_root = defaultdict(list)
    for msg in messages:
        by_root[msg["thread_root_id"]].append(msg)

    # Sort messages within each thread by date (best-effort; keep order if date parse fails)
    for root_id, thread_msgs in by_root.items():
        thread_msgs.sort(key=lambda m: (m["date"], m["msg_num"]))

    # Build thread list with summary
    threads = []
    for root_id, thread_msgs in by_root.items():
        thread_msgs_sorted = sorted(thread_msgs, key=lambda m: (m["date"], m["msg_num"]))
        root_msg = thread_msgs_sorted[0]
        threads.append({
            "thread_root_id": root_id,
            "subject": root_msg["subject"],
            "base_subject": root_msg["base_subject"],
            "message_count": len(thread_msgs),
            "message_numbers": [m["msg_num"] for m in thread_msgs_sorted],
            "messages": thread_msgs_sorted,
        })

    threads.sort(key=lambda t: (-t["message_count"], t["subject"]))

    unique_threads = len(threads)
    total_messages = len(messages)

    print(f"Total messages:     {total_messages}")
    print(f"Unique threads:     {unique_threads}")
    if args.csv:
        import csv as csv_module
        w = csv_module.writer(sys.stdout)
        w.writerow(["thread_root_id", "subject", "message_count"])
        for t in threads:
            w.writerow([t["thread_root_id"], t["subject"], t["message_count"]])
    else:
        print()
        print("Threads (by message count, then subject):")
        print("-" * 72)
        for i, t in enumerate(threads, 1):
            print(f"  {i:3}. [{t['message_count']:3} msgs] {t['subject'][:60]}")
        print("-" * 72)

    if args.by_subject:
        by_base = defaultdict(list)
        for msg in messages:
            by_base[msg["base_subject"]].append(msg)
        print()
        print(f"Grouped by base subject (fallback): {len(by_base)} groups")

    if args.out:
        out_data = {
            "total_messages": total_messages,
            "unique_threads": unique_threads,
            "threads": [
                {
                    "thread_root_id": t["thread_root_id"],
                    "subject": t["subject"],
                    "base_subject": t["base_subject"],
                    "message_count": t["message_count"],
                    "message_numbers": t["message_numbers"],
                    "messages": t["messages"],
                }
                for t in threads
            ],
        }
        out_path = Path(args.out)
        out_path.write_text(json.dumps(out_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nThread summary written to: {out_path}")


if __name__ == "__main__":
    main()
