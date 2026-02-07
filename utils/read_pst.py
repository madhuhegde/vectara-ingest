#!/usr/bin/env python3
"""
Read PST files and dump extracted message data as text for verification.
Uses libratom (PffArchive) to parse .pst files in a given directory.

Run with the vectara_emails_env venv (where libratom is installed):
  source ~/work/vectara/vectara_emails_env/bin/activate
  python utils/read_pst.py [options]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

def _sanitize_filename(name: str, max_len: int = 200) -> str:
    """Make a safe filename: remove path chars and control chars."""
    if not name or not name.strip():
        return "attachment"
    name = name.strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = name[:max_len].strip() or "attachment"
    return name


def _extract_attachments(message, archive, msg_count, pst_path, attachments_dir: str, rel_to: Path = None):
    """Extract attachments to attachments_dir. Returns list of {name, size, mime_type, path} (path relative if rel_to)."""
    base = Path(attachments_dir)
    pst_stem = pst_path.stem
    out_dir = base / _sanitize_filename(pst_stem, 100)
    out_dir.mkdir(parents=True, exist_ok=True)
    attachments = []
    if hasattr(message, "attachments"):
        try:
            attachments = list(message.attachments)
        except (OSError, ValueError):
            pass
    if not attachments and getattr(message, "number_of_attachments", 0):
        try:
            for i in range(message.number_of_attachments):
                att = message.get_attachment(i)
                attachments.append(att)
        except (OSError, ValueError, AttributeError):
            pass
    result = []
    try:
        meta_list = archive.get_attachment_metadata(message)
    except Exception:
        meta_list = []
    for i, att in enumerate(attachments):
        try:
            size = getattr(att, "size", None) or (getattr(att, "get_size", lambda: 0)() or 0)
            if not size:
                continue
            name = getattr(att, "name", None)
            name = _to_str(name).strip() if name else ""
            safe_name = _sanitize_filename(name) if name else f"attachment_{i}"
            out_name = f"msg_{msg_count:04d}_{i:02d}_{safe_name}"
            out_path = out_dir / out_name
            data = att.read_buffer(size)
            if data:
                out_path.write_bytes(data)
            mime = meta_list[i].mime_type if i < len(meta_list) else None
            if rel_to:
                try:
                    path_str = str(Path(out_path).resolve().relative_to(Path(rel_to).resolve()))
                except ValueError:
                    path_str = str(out_path)
            else:
                path_str = str(out_path)
            result.append({"name": name or out_name, "size": size, "mime_type": mime, "path": path_str})
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    return result


def _to_str(value):
    """Convert to str; decode bytes with utf-8/utf-16 if needed."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        for enc in ("utf-8", "utf-16", "utf-16-le", "latin-1"):
            try:
                return value.decode(enc, errors="replace")
            except (UnicodeDecodeError, LookupError):
                continue
        return value.decode("utf-8", errors="replace")
    return str(value)


def _parse_useful_headers(raw_headers) -> dict:
    """Extract only From, To, Cc from transport headers; ignore X-*, ARC-*, DKIM, etc."""
    out = {}
    if not raw_headers:
        return out
    raw = _to_str(raw_headers)
    for line in raw.splitlines():
        if line.startswith((" ", "\t")):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "from" and "from" not in out:
            out["from"] = value
        elif key == "to" and "to" not in out:
            out["to"] = value
        elif key == "cc" and "cc" not in out:
            out["cc"] = value
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Read PST files and dump message data for verification."
    )
    parser.add_argument(
        "-i", "--input",
        default=os.path.expanduser("~/work/vectara/vectara_emails/3d-fp-users.pdl-1"),
        help="Folder containing .pst files, or path to a single .pst file",
    )
    parser.add_argument(
        "-o", "--out",
        default=None,
        help="Optional file path to write dump (default: print to stdout only)",
    )
    parser.add_argument(
        "--max-body",
        type=int,
        default=0,
        help="Max characters of body per message (0 = no limit, full extraction). Default: 0",
    )
    parser.add_argument(
        "--attachments-dir",
        default=None,
        metavar="DIR",
        help="Extract attachments (images, documents, etc.) into this directory",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format: text (default) or json for RAG/ingestion",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"Error: path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        from libratom.lib.pff import PffArchive
    except ImportError as e:
        print(
            "Error: libratom is required. Use vectara_emails_env and run: pip install libratom",
            file=sys.stderr,
        )
        print(f"ImportError: {e}", file=sys.stderr)
        sys.exit(1)

    if input_path.is_dir():
        pst_files = sorted(input_path.glob("*.pst"))
        if not pst_files:
            print(f"No .pst files found in {input_path}", file=sys.stderr)
            sys.exit(1)
    elif input_path.is_file():
        if input_path.suffix.lower() != ".pst":
            print(f"Error: not a .pst file: {input_path}", file=sys.stderr)
            sys.exit(1)
        pst_files = [input_path]
    else:
        print(f"Error: not a folder or file: {input_path}", file=sys.stderr)
        sys.exit(1)

    out_handle = open(args.out, "w", encoding="utf-8", errors="replace") if args.out else None
    json_messages = []
    total_messages = 0
    rel_to = Path(args.out).resolve().parent if (args.out and args.format == "json") else None
    try:
        def emit(text: str) -> None:
            if out_handle and args.format == "text":
                out_handle.write(text + "\n")

        for pst_path in pst_files:
            pst_size = pst_path.stat().st_size
            emit("")
            emit("=" * 72)
            emit(f"PST: {pst_path.name}")
            emit(f"PST file size: {pst_size:,} bytes ({pst_size / (1024*1024):.2f} MB)")
            emit("=" * 72)

            try:
                with PffArchive(pst_path) as archive:
                    try:
                        archive_total = archive.message_count
                    except Exception:
                        archive_total = None
                    msg_count = 0
                    for folder in archive.folders():
                        folder_name = _to_str(getattr(folder, "name", None) or "Unknown")
                        emit(f"\n--- Folder: {folder_name} ---")
                        try:
                            for message in folder.sub_messages:
                                msg_count += 1
                                subject = _to_str(getattr(message, "subject", None) or "(no subject)")
                                try:
                                    date_val = PffArchive.get_message_date(message)
                                    date_str = date_val.isoformat() if date_val else "(no date)"
                                except Exception:
                                    date_str = "(date error)"
                                body, _ = PffArchive.get_message_body(message)
                                body = _to_str(body or "").strip()
                                if args.max_body and len(body) > args.max_body:
                                    body = body[: args.max_body] + "..."
                                body = body.replace("\r\n", "\n").replace("\r", "\n")

                                if args.format == "json":
                                    raw_headers = getattr(message, "transport_headers", None)
                                    useful = _parse_useful_headers(raw_headers)
                                    att_list = []
                                    if args.attachments_dir:
                                        try:
                                            att_list = _extract_attachments(
                                                message, archive, msg_count, pst_path,
                                                args.attachments_dir, rel_to=rel_to
                                            )
                                        except Exception:
                                            pass
                                    if not att_list:
                                        try:
                                            for m in archive.get_attachment_metadata(message):
                                                att_list.append({
                                                    "name": m.name, "size": m.size, "mime_type": m.mime_type,
                                                    "path": None
                                                })
                                        except Exception:
                                            pass
                                    json_messages.append({
                                        "message_id": f"{pst_path.stem}_msg_{msg_count:04d}",
                                        "folder": folder_name,
                                        "subject": subject,
                                        "date": date_str,
                                        "from": useful.get("from"),
                                        "to": useful.get("to"),
                                        "cc": useful.get("cc"),
                                        "body": body or "",
                                        "attachments": att_list,
                                    })
                                    continue

                                emit(f"  [{msg_count}] Subject: {subject}")
                                emit(f"      Date: {date_str}")
                                raw_headers = getattr(message, "transport_headers", None)
                                if raw_headers:
                                    headers = _to_str(raw_headers).strip()
                                    emit(f"      Headers: {headers}")
                                emit(f"      Body: {body or '(empty)'}")
                                try:
                                    num_att = getattr(message, "number_of_attachments", 0) or 0
                                    if num_att:
                                        emit(f"      Attachments: {num_att}")
                                        meta_list = archive.get_attachment_metadata(message)
                                        for m in meta_list:
                                            emit(f"        - {m.name} ({m.size} bytes, {m.mime_type or '?'})")
                                except Exception:
                                    pass
                                if args.attachments_dir:
                                    try:
                                        _extract_attachments(
                                            message, archive, msg_count, pst_path, args.attachments_dir
                                        )
                                    except Exception as e:
                                        emit(f"      (Attachment extraction error: {e})")
                                emit("")
                        except OSError as e:
                            emit(f"  (OSError reading folder messages: {e})")
                    emit(f"\nTotal messages extracted: {msg_count}")
                    if archive_total is not None:
                        match = "YES" if msg_count == archive_total else "NO"
                        emit(f"Archive message_count (expected): {archive_total}")
                        emit(f"All messages extracted: {match}")
                    total_messages += msg_count

            except OSError as e:
                emit(f"Failed to open PST: {e}")
            except Exception as e:
                emit(f"Error: {e}")

    finally:
        if out_handle:
            if args.format == "json":
                json.dump(json_messages, out_handle, indent=2, ensure_ascii=False)
            out_handle.close()
            out_path = Path(args.out)
            if out_path.exists():
                out_size = out_path.stat().st_size
                print(
                    f"\nTotal emails (messages) extracted: {total_messages}",
                    file=sys.stderr,
                )
                print(
                    f"Dump written to: {args.out} ({out_size:,} bytes, {out_size / (1024*1024):.2f} MB)",
                    file=sys.stderr,
                )
                print(
                    "Note: PST file size is much larger than the text dump (attachments, indexes, format overhead are not extracted as text).",
                    file=sys.stderr,
                )
            else:
                print(f"\nDump also written to: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
