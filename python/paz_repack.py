"""PAZ asset repacker for Crimson Desert.

Patches modified files back into PAZ archives. Handles encryption and
compression to produce output the game will accept.

Pipeline: modified file -> LZ4 compress -> ChaCha20 encrypt -> write to PAZ

Constraints:
  - Encrypted blob must be exactly comp_size bytes (original size in PAMT)
  - Decompressed output must be exactly orig_size bytes
  - PAMT files must never be modified (game integrity check)
  - NTFS timestamps on .paz files must be preserved

Usage:
    # Repack using PAMT metadata (recommended)
    python paz_repack.py modified.xml --pamt 0.pamt --paz-dir ./0003 \
        --entry "technique/rendererconfiguration.xml"

    # Repack to a standalone file (for testing)
    python paz_repack.py modified.xml --pamt 0.pamt --paz-dir ./0003 \
        --entry "technique/rendererconfiguration.xml" --output repacked.bin

Library usage:
    from paz_repack import repack_entry
    from paz_parse import parse_pamt

    entries = parse_pamt("0.pamt", paz_dir="./0003")
    entry = next(e for e in entries if "rendererconfiguration" in e.path)
    repack_entry("modified.xml", entry)
"""

import os
import sys
import struct
import ctypes
import argparse

import lz4.block

from paz_parse import parse_pamt, PazEntry
from paz_crypto import encrypt, lz4_compress


# ── Timestamp preservation (Windows) ────────────────────────────────

def _save_timestamps(path: str):
    """Capture NTFS timestamps. Returns a callable to restore them."""
    if sys.platform != 'win32':
        return lambda: None

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

    OPEN_EXISTING = 3
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_ATTR = 0x80 | 0x02000000  # NORMAL | BACKUP_SEMANTICS

    h = kernel32.CreateFileW(path, GENERIC_READ, 1, None, OPEN_EXISTING, FILE_ATTR, None)
    if h == -1:
        return lambda: None

    ct, at, mt = FILETIME(), FILETIME(), FILETIME()
    kernel32.GetFileTime(h, ctypes.byref(ct), ctypes.byref(at), ctypes.byref(mt))
    kernel32.CloseHandle(h)

    def restore():
        h2 = kernel32.CreateFileW(path, GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTR, None)
        if h2 != -1:
            kernel32.SetFileTime(h2, ctypes.byref(ct), ctypes.byref(at), ctypes.byref(mt))
            kernel32.CloseHandle(h2)

    return restore


# ── Size matching ────────────────────────────────────────────────────

def _pad_to_orig_size(data: bytes, orig_size: int) -> bytes:
    """Pad data to exactly orig_size bytes with zero bytes."""
    if len(data) >= orig_size:
        return data[:orig_size]
    return data + b'\x00' * (orig_size - len(data))


def _shrink_to_orig_size(data: bytes, orig_size: int) -> bytes:
    """Shrink XML data to exactly orig_size by removing comment content
    and collapsing redundant whitespace.

    Removes bytes from the end of XML comments first (replacing the
    comment body with fewer characters). If that's not enough, collapses
    runs of multiple spaces/tabs into single spaces.

    Returns:
        data trimmed to exactly orig_size bytes

    Raises:
        ValueError if the data can't be shrunk enough
    """
    if len(data) <= orig_size:
        return _pad_to_orig_size(data, orig_size)

    excess = len(data) - orig_size
    result = bytearray(data)

    # Phase 1: trim comment bodies from the end (preserve <!-- -->)
    comments = _find_xml_comments(bytes(result))
    # Process largest comments first for maximum yield
    comments.sort(key=lambda c: c[1] - c[0], reverse=True)

    for cstart, cend in comments:
        if excess <= 0:
            break
        body_len = cend - cstart
        # Keep at least 1 space in the comment so it stays valid
        removable = body_len - 1
        if removable <= 0:
            continue
        to_remove = min(removable, excess)
        # Replace the end of the comment body with nothing
        result[cstart + 1:cstart + 1 + to_remove] = b''
        excess -= to_remove
        if excess <= 0:
            break
        # Recalculate comments since offsets shifted
        comments = _find_xml_comments(bytes(result))
        comments.sort(key=lambda c: c[1] - c[0], reverse=True)

    if excess <= 0:
        return bytes(result[:orig_size]) if len(result) >= orig_size else \
            bytes(result) + b'\x00' * (orig_size - len(result))

    # Phase 2: collapse runs of 2+ whitespace chars into single space
    i = len(result) - 1
    while i > 0 and excess > 0:
        if result[i] in (0x20, 0x09) and result[i - 1] in (0x20, 0x09):
            # Found consecutive whitespace, remove one
            del result[i]
            excess -= 1
        i -= 1

    if excess <= 0:
        return bytes(result[:orig_size]) if len(result) >= orig_size else \
            bytes(result) + b'\x00' * (orig_size - len(result))

    # Phase 3: remove entire empty comments (<!-- ... --> -> nothing)
    comments = _find_xml_comments(bytes(result))
    for cstart, cend in comments:
        if excess <= 0:
            break
        # Remove <!-- + body + -->  (4 + body_len + 3 bytes)
        full_start = cstart - 4
        full_end = cend + 3
        removable = full_end - full_start
        if removable <= excess + 7:  # worth removing the whole comment
            to_remove = min(removable, excess)
            # Just remove bytes from the comment
            result[full_start:full_start + to_remove] = b''
            excess -= to_remove
            if excess <= 0:
                break
            comments = _find_xml_comments(bytes(result))

    if len(result) > orig_size:
        raise ValueError(
            f"Modified file is {len(data) - orig_size} bytes over orig_size "
            f"({orig_size}). Could only trim {len(data) - len(result)} bytes "
            f"from comments and whitespace. Reduce content manually.")

    return bytes(result) + b'\x00' * (orig_size - len(result))


def _find_xml_comments(data: bytes) -> list[tuple[int, int]]:
    """Find all XML comment bodies (content between <!-- and -->).

    Returns list of (start, end) byte offsets for the comment content
    (not including the delimiters themselves).
    """
    comments = []
    search_from = 0
    while True:
        start = data.find(b'<!--', search_from)
        if start == -1:
            break
        content_start = start + 4
        end = data.find(b'-->', content_start)
        if end == -1:
            break
        if end > content_start:
            comments.append((content_start, end))
        search_from = end + 3
    return comments


def _make_incompressible(length: int) -> bytes:
    """Generate incompressible byte content for padding comments."""
    # Cycle through printable ASCII that won't form LZ4 matches
    out = bytearray(length)
    for i in range(length):
        out[i] = 33 + ((i * 7 + i // 3) % 93)  # varied printable ASCII
    return bytes(out)


def _inflate_with_comments(padded: bytes, plaintext_len: int,
                           target_comp_size: int,
                           target_orig_size: int) -> bytes | None:
    """Insert XML comments with incompressible content to inflate compressed size.

    First tries replacing trailing padding with a new <!-- ... --> comment.
    If there's not enough trailing room, expands existing comment bodies
    by replacing their content with less compressible bytes.

    Returns adjusted data or None if it can't hit the target.
    """
    # Strategy 1: new comment in trailing padding
    padding_room = target_orig_size - plaintext_len
    if padding_room >= 7:
        max_body = padding_room - 7
        lo, hi = 0, max_body
        while lo <= hi:
            mid = (lo + hi) // 2
            body = _make_incompressible(mid)
            comment = b'<!--' + body + b'-->'
            trial = padded[:plaintext_len] + comment
            if len(trial) < target_orig_size:
                trial = trial + b'\x00' * (target_orig_size - len(trial))
            else:
                trial = trial[:target_orig_size]
            c = lz4.block.compress(trial, store_size=False)
            if len(c) == target_comp_size:
                return trial
            elif len(c) < target_comp_size:
                lo = mid + 1
            else:
                hi = mid - 1

        for n in range(max(0, lo - 20), min(lo + 20, max_body + 1)):
            body = _make_incompressible(n)
            comment = b'<!--' + body + b'-->'
            trial = padded[:plaintext_len] + comment
            if len(trial) < target_orig_size:
                trial = trial + b'\x00' * (target_orig_size - len(trial))
            else:
                trial = trial[:target_orig_size]
            c = lz4.block.compress(trial, store_size=False)
            if len(c) == target_comp_size:
                return trial

    # Strategy 2: replace content inside existing comments with
    # incompressible bytes to inflate compressed size
    comments = _find_xml_comments(padded)
    if not comments:
        return None

    # Sort by size descending — largest comments give most room to tune
    comments.sort(key=lambda c: c[1] - c[0], reverse=True)

    for cstart, cend in comments:
        body_len = cend - cstart
        if body_len < 1:
            continue

        # Binary search: replace N bytes of comment body with incompressible
        lo, hi = 0, body_len
        while lo <= hi:
            mid = (lo + hi) // 2
            trial = bytearray(padded)
            fill = _make_incompressible(mid)
            trial[cstart:cstart + mid] = fill
            c = lz4.block.compress(bytes(trial), store_size=False)
            if len(c) == target_comp_size:
                return bytes(trial)
            elif len(c) < target_comp_size:
                lo = mid + 1
            else:
                hi = mid - 1

        # Linear scan near boundary
        for n in range(max(0, lo - 20), min(lo + 20, body_len + 1)):
            trial = bytearray(padded)
            fill = _make_incompressible(n)
            trial[cstart:cstart + n] = fill
            c = lz4.block.compress(bytes(trial), store_size=False)
            if len(c) == target_comp_size:
                return bytes(trial)

    return None


def _match_compressed_size(plaintext: bytes, target_comp_size: int,
                           target_orig_size: int) -> bytes:
    """Adjust plaintext so it compresses to exactly target_comp_size.

    If the plaintext is larger than target_orig_size, trims comment content
    and whitespace to fit. Then finds individual byte positions where
    replacing with a space changes the LZ4 compressed output to exactly
    the target.

    Returns:
        adjusted plaintext (exactly target_orig_size bytes)

    Raises:
        ValueError if size matching fails
    """
    if len(plaintext) > target_orig_size:
        padded = _shrink_to_orig_size(plaintext, target_orig_size)
    else:
        padded = _pad_to_orig_size(plaintext, target_orig_size)

    comp = lz4.block.compress(padded, store_size=False)
    if len(comp) == target_comp_size:
        return padded

    delta = len(comp) - target_comp_size  # positive = need to shrink

    # Collect candidate positions: comment bytes first, then all non-space bytes
    comments = _find_xml_comments(padded)
    comment_positions = set()
    for cstart, cend in comments:
        for i in range(cstart, cend):
            if padded[i:i+1] != b' ':
                comment_positions.add(i)

    # Try comment positions first (safest), then scan all positions
    candidates = sorted(comment_positions)
    candidates_set = set(candidates)

    # Phase 1: single-byte replacements in comments
    for i in candidates:
        trial = bytearray(padded)
        trial[i] = 0x20
        c = lz4.block.compress(bytes(trial), store_size=False)
        if len(c) == target_comp_size:
            return bytes(trial)

    # Phase 2: single-byte replacements across the whole file
    # Sample positions evenly to avoid scanning all 290k bytes
    step = max(1, len(padded) // 5000)
    for i in range(0, len(padded), step):
        if padded[i:i+1] == b' ' or i in candidates_set:
            continue
        trial = bytearray(padded)
        trial[i] = 0x20
        c = lz4.block.compress(bytes(trial), store_size=False)
        if len(c) == target_comp_size:
            return bytes(trial)

    # Phase 3: full scan if sampling missed
    for i in range(len(padded)):
        if padded[i:i+1] == b' ' or i in candidates_set:
            continue
        trial = bytearray(padded)
        trial[i] = 0x20
        c = lz4.block.compress(bytes(trial), store_size=False)
        if len(c) == target_comp_size:
            return bytes(trial)

    # Phase 4: try multi-byte replacements for larger deltas
    if abs(delta) > 1:
        # Binary search over number of comment bytes to replace
        lo, hi = 0, len(candidates)
        while lo <= hi:
            mid = (lo + hi) // 2
            trial = bytearray(padded)
            for idx in candidates[:mid]:
                trial[idx] = 0x20
            c = lz4.block.compress(bytes(trial), store_size=False)
            if len(c) == target_comp_size:
                return bytes(trial)
            elif len(c) > target_comp_size:
                lo = mid + 1
            else:
                hi = mid - 1

        # Linear scan near boundary
        for n in range(max(0, lo - 20), min(lo + 20, len(candidates) + 1)):
            trial = bytearray(padded)
            for idx in candidates[:n]:
                trial[idx] = 0x20
            c = lz4.block.compress(bytes(trial), store_size=False)
            if len(c) == target_comp_size:
                return bytes(trial)

    # Phase 5: inflate compressed size by inserting XML comments with
    # incompressible content into the trailing padding region.
    # Used when the modified file compresses smaller than the target.
    if delta < 0:
        result = _inflate_with_comments(padded, len(plaintext),
                                        target_comp_size, target_orig_size)
        if result is not None:
            return result

    raise ValueError(
        f"Cannot match target comp_size {target_comp_size} "
        f"(got {len(comp)}, delta {delta})")


# ── Core repack ──────────────────────────────────────────────────────

def repack_entry(modified_path: str, entry: PazEntry,
                 output_path: str = None, dry_run: bool = False) -> dict:
    """Repack a modified file and patch it into the PAZ archive.

    Args:
        modified_path: path to the modified plaintext file
        entry: PAMT entry for the file being replaced
        output_path: if set, write to this file instead of patching the PAZ
        dry_run: if True, compute sizes but don't write anything

    Returns:
        dict with repack stats
    """
    with open(modified_path, 'rb') as f:
        plaintext = f.read()

    basename = os.path.basename(entry.path)
    is_compressed = entry.compressed and entry.compression_type == 2

    if is_compressed:
        # Need to match both orig_size and comp_size exactly
        adjusted = _match_compressed_size(plaintext, entry.comp_size, entry.orig_size)
        compressed = lz4.block.compress(adjusted, store_size=False)
        assert len(compressed) == entry.comp_size, \
            f"Size mismatch: {len(compressed)} != {entry.comp_size}"
        payload = compressed
    else:
        # Uncompressed: pad/truncate to comp_size, zero-pad remainder
        if len(plaintext) > entry.comp_size:
            raise ValueError(
                f"Modified file ({len(plaintext)} bytes) exceeds budget "
                f"({entry.comp_size} bytes). Reduce content.")
        payload = plaintext + b'\x00' * (entry.comp_size - len(plaintext))

    # Encrypt if it's an XML file
    if entry.encrypted:
        payload = encrypt(payload, basename)

    result = {
        "entry_path": entry.path,
        "modified_size": len(plaintext),
        "comp_size": entry.comp_size,
        "orig_size": entry.orig_size,
        "compressed": is_compressed,
        "encrypted": entry.encrypted,
    }

    if dry_run:
        result["action"] = "dry_run"
        return result

    if output_path:
        # Write to standalone file
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(payload)
        result["action"] = "written"
        result["output"] = output_path
    else:
        # Patch directly into PAZ archive
        restore_ts = _save_timestamps(entry.paz_file)

        with open(entry.paz_file, 'r+b') as f:
            f.seek(entry.offset)
            f.write(payload)

        restore_ts()
        result["action"] = "patched"
        result["paz_file"] = entry.paz_file
        result["offset"] = f"0x{entry.offset:08X}"

    return result


# ── CLI ──────────────────────────────────────────────────────────────

def find_entry(entries: list[PazEntry], entry_path: str) -> PazEntry:
    """Find a PAMT entry by path (case-insensitive, partial match)."""
    entry_path = entry_path.lower().replace('\\', '/')

    # Exact match first
    for e in entries:
        if e.path.lower().replace('\\', '/') == entry_path:
            return e

    # Partial match (basename or suffix)
    matches = [e for e in entries if entry_path in e.path.lower().replace('\\', '/')]
    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        print(f"Ambiguous entry path '{entry_path}', matches:", file=sys.stderr)
        for m in matches[:10]:
            print(f"  {m.path}", file=sys.stderr)
        if len(matches) > 10:
            print(f"  ... ({len(matches) - 10} more)", file=sys.stderr)
        sys.exit(1)

    print(f"Entry not found: '{entry_path}'", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Repack a modified file into a PAZ archive",
        epilog="Example: python paz_repack.py modified.xml --pamt 0.pamt "
               "--paz-dir ./0003 --entry technique/rendererconfiguration.xml")
    parser.add_argument("modified", help="Path to modified file")
    parser.add_argument("--pamt", required=True, help="Path to .pamt index file")
    parser.add_argument("--paz-dir", help="Directory containing .paz files")
    parser.add_argument("--entry", required=True,
                        help="Entry path within the archive (or partial match)")
    parser.add_argument("--output", help="Write to file instead of patching PAZ")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would happen without writing")
    args = parser.parse_args()

    entries = parse_pamt(args.pamt, paz_dir=args.paz_dir)
    entry = find_entry(entries, args.entry)

    print(f"Entry:      {entry.path}")
    print(f"PAZ:        {entry.paz_file} @ 0x{entry.offset:08X}")
    print(f"comp_size:  {entry.comp_size:,}")
    print(f"orig_size:  {entry.orig_size:,}")
    print(f"Compressed: {'LZ4' if entry.compressed else 'no'}")
    print(f"Encrypted:  {'yes' if entry.encrypted else 'no'}")
    print()

    try:
        result = repack_entry(args.modified, entry,
                              output_path=args.output,
                              dry_run=args.dry_run)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if result["action"] == "dry_run":
        print("Dry run — no changes made.")
    elif result["action"] == "written":
        print(f"Written to {result['output']}")
    elif result["action"] == "patched":
        print(f"Patched {result['paz_file']} at {result['offset']}")

    print(f"Modified file: {result['modified_size']:,} bytes")


if __name__ == "__main__":
    main()
