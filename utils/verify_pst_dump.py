#!/usr/bin/env python3
"""
Verify pst_dump.txt: count distinct subjects and check each message
contains "3d-fp-users.pdl@broadcom.com" in headers.
"""
import re
import sys
from pathlib import Path

def main():
    dump_path = Path(__file__).parent.parent / "pst_dump.txt"
    if len(sys.argv) > 1:
        dump_path = Path(sys.argv[1])

    text = dump_path.read_text(encoding="utf-8", errors="replace")
    # Message blocks: "  [N] Subject: ..." then Headers: ... then Body: ...
    msg_pattern = re.compile(
        r"\s+\[(\d+)\]\s+Subject:\s*(.+?)(?=\n)"
        r"(.*?)(?=\s+Body:)",
        re.DOTALL,
    )
    address = "3d-fp-users.pdl@broadcom.com"
    address_lower = address.lower()

    messages = []
    for m in msg_pattern.finditer(text):
        msg_num = int(m.group(1))
        subject = m.group(2).strip()
        header_body = m.group(3)
        has_address = address_lower in header_body.lower()
        messages.append(
            {"num": msg_num, "subject": subject, "has_address": has_address}
        )

    total = len(messages)
    distinct_subjects = len({msg["subject"] for msg in messages})
    with_address = sum(1 for msg in messages if msg["has_address"])
    missing_address = [msg for msg in messages if not msg["has_address"]]

    print(f"Total messages in dump: {total}")
    print(f"Distinct subjects:       {distinct_subjects}")
    print(f"Messages containing '{address}' in headers: {with_address}")
    print(f"Messages missing that address: {len(missing_address)}")
    if missing_address:
        print("\nMessage numbers missing the address:")
        for msg in missing_address:
            print(f"  [{msg['num']}] {msg['subject'][:70]}")

if __name__ == "__main__":
    main()
