#!/usr/bin/env python3
"""
Compute message and thread size analytics from a PST text dump.
- Message/thread: character counts (body only, headers excluded).
- Attachments: total count, types (by MIME type), min/max/avg size per type.
"""
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
    """Extract Message-IDs from a header value (angle-bracket form)."""
    if not value:
        return []
    ids = re.findall(r"<([^>]+)>", value)
    return [i.strip() for i in ids if "@" in i]


def main():
    dump_path = Path(__file__).resolve().parent.parent / "fe_pdl_users_dump.txt"
    if len(sys.argv) > 1:
        dump_path = Path(sys.argv[1])
    if not dump_path.exists():
        print(f"Error: file not found: {dump_path}", file=sys.stderr)
        sys.exit(1)

    text = dump_path.read_text(encoding="utf-8", errors="replace")

    block_pattern = re.compile(
        r"\n\s+\[(\d+)\]\s+Subject:\s*(.+?)(?=\n)"
        r"(.*?)(?=\n\s+\[\d+\]\s+Subject:|\Z)",
        re.DOTALL,
    )
    blocks = list(block_pattern.finditer(text))

    message_sizes = []  # character count per message
    thread_sizes = defaultdict(int)  # thread_root_id -> total chars

    for m in blocks:
        msg_num = int(m.group(1))
        rest = m.group(3)
        body_match = re.search(r"\n\s*Body:\s*(.*)", rest, re.DOTALL)
        body_text = (body_match.group(1) or "").strip()
        char_count = len(body_text)
        message_sizes.append(char_count)

        headers_match = re.search(r"Headers:\s*(.*?)(?=\n\s+Body:)", rest, re.DOTALL)
        header_text = headers_match.group(1).strip() if headers_match else ""
        headers = _parse_headers(header_text)

        message_id = headers.get("message-id", "").strip()
        mid_list = _extract_message_ids(message_id)
        this_mid = mid_list[0] if mid_list else f"__no_mid_{msg_num}"

        ref_ids = _extract_message_ids(headers.get("references", "").strip())
        in_reply_to_ids = _extract_message_ids(headers.get("in-reply-to", "").strip())

        if ref_ids:
            thread_root_id = ref_ids[0]
        elif in_reply_to_ids:
            thread_root_id = in_reply_to_ids[0]
        else:
            thread_root_id = this_mid

        thread_sizes[thread_root_id] += char_count

    n_msg = len(message_sizes)
    n_thread = len(thread_sizes)
    thread_char_list = list(thread_sizes.values())

    def stats(name: str, values: list) -> None:
        if not values:
            print(f"  {name}: (no data)")
            return
        print(f"  Min:    {min(values):,} chars")
        print(f"  Max:    {max(values):,} chars")
        print(f"  Average: {sum(values) / len(values):,.0f} chars")

    print(f"Dump: {dump_path.name}")
    print(f"Messages: {n_msg:,}")
    print()
    print("Message size (body only, headers excluded):")
    stats("message", message_sizes)
    print()
    print(f"Threads: {n_thread:,}")
    print("Thread size (sum of message body sizes in thread):")
    stats("thread", thread_char_list)

    # Attachment analytics: parse "        - name (SIZE bytes, mime_type)" lines
    att_line_re = re.compile(r"^\s+-\s+.+?\s+\((\d+)\s+bytes,\s*([^)]+)\)\s*$", re.MULTILINE)
    att_by_type = defaultdict(list)  # mime_type -> [sizes in bytes]
    for mat in att_line_re.finditer(text):
        size = int(mat.group(1))
        mime = (mat.group(2) or "").strip() or "unknown"
        att_by_type[mime].append(size)

    total_attachments = sum(len(sizes) for sizes in att_by_type.values())
    if total_attachments:
        print()
        print("Attachments:")
        print(f"  Total count: {total_attachments:,}")
        print(f"  Unique types (MIME): {len(att_by_type):,}")
        print()
        print("Per type (min / max / average size in bytes):")
        print("-" * 72)
        for mime in sorted(att_by_type.keys(), key=lambda m: (-len(att_by_type[m]), m)):
            sizes = att_by_type[mime]
            n = len(sizes)
            mn, mx = min(sizes), max(sizes)
            avg = sum(sizes) / n
            print(f"  {mime}")
            print(f"    count: {n:,}  |  min: {mn:,}  max: {mx:,}  avg: {avg:,.0f} bytes")
        print("-" * 72)


if __name__ == "__main__":
    main()
