#!/usr/bin/env python3
"""Split a PDF into chunks by page, each chunk under a given size (MB)."""
import argparse
import io
import os
import sys
from pypdf import PdfReader, PdfWriter

def split_pdf_by_size(input_path, max_size_mb=4, out_dir="."):
    # Convert MB to bytes (using a safety margin of 0.2MB to account for PDF overhead)
    max_bytes = (max_size_mb - 0.2) * 1024 * 1024

    os.makedirs(out_dir, exist_ok=True)
    output_stem = os.path.splitext(os.path.basename(input_path))[0]
   
    reader = PdfReader(input_path)
    total_pages = len(reader.pages)
   
    current_writer = PdfWriter()
    current_chunk_index = 1
    current_size = 0
   
    print(f"Processing {input_path} ({total_pages} pages)...")
   
    for i, page in enumerate(reader.pages):
        # We need to simulate adding the page to check the size
        # pypdf doesn't allow 'removing' pages easily, so we use a temporary writer
        # to estimate, or we accept a slight performance hit to verify the chunk size.
       
        current_writer.add_page(page)
       
        # Write to a temporary memory buffer to check the size
        temp_buffer = io.BytesIO()
        current_writer.write(temp_buffer)
        temp_size = temp_buffer.tell()
       
        # If adding this page pushed us over the limit
        if temp_size > max_bytes:
            # Case 1: The writer has multiple pages, and this last one broke the camel's back.
            if len(current_writer.pages) > 1:
                # We need to remove the last page we just added (not supported natively),
                # so we actually have to save the *previous* state.
                # Since we can't "undo", the efficient way is to reconstruct the writer
                # or prevent adding it in the first place.
               
                # RESTART STRATEGY:
                # Since we added it and are now over size, we basically need to save
                # the chunk *without* this latest page.
               
                # 1. Create a writer for the valid chunk (all pages except current)
                valid_writer = PdfWriter()
                for p in current_writer.pages[:-1]:
                    valid_writer.add_page(p)
               
                # 2. Save the valid chunk
                output_filename = os.path.join(out_dir, f"{output_stem}_chunk_{current_chunk_index}.pdf")
                with open(output_filename, "wb") as f:
                    valid_writer.write(f)
                print(f"Saved {output_filename}")
               
                # 3. Start a new writer with ONLY the current page that caused the overflow
                current_writer = PdfWriter()
                current_writer.add_page(page)
                current_chunk_index += 1
               
            # Case 2: A SINGLE page is larger than the limit (e.g., 6MB image scan)
            else:
                # We have no choice but to save this single huge page as its own chunk
                output_filename = os.path.join(out_dir, f"{output_stem}_chunk_{current_chunk_index}.pdf")
                with open(output_filename, "wb") as f:
                    current_writer.write(f)
                print(f"Warning: Page {i+1} alone exceeds size limit. Saved as {output_filename}")
               
                # Reset for next page
                current_writer = PdfWriter()
                current_chunk_index += 1

    # Save any remaining pages in the buffer
    if len(current_writer.pages) > 0:
        output_filename = os.path.join(out_dir, f"{output_stem}_chunk_{current_chunk_index}.pdf")
        with open(output_filename, "wb") as f:
            current_writer.write(f)
        print(f"Saved {output_filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Split a PDF into chunks by page, each under a given size (MB)."
    )
    parser.add_argument(
        "-f", "--filename",
        required=True,
        help="Path to the input PDF file",
    )
    parser.add_argument(
        "-s", "--size",
        type=float,
        required=True,
        dest="size_mb",
        help="Maximum size per output chunk in megabytes (e.g. 5 for 5 MB)",
    )
    parser.add_argument(
        "--out_dir",
        default=".",
        help="Directory for output chunk files (default: current directory)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.filename):
        print(f"Error: File not found: {args.filename}", file=sys.stderr)
        sys.exit(1)
    if args.size_mb <= 0:
        print("Error: size_mb must be positive", file=sys.stderr)
        sys.exit(1)

    split_pdf_by_size(args.filename, max_size_mb=args.size_mb, out_dir=args.out_dir)


if __name__ == "__main__":
    main()
