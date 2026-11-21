"""Removes the APK Signing Block from a signed APK, giving back the unsigned APK it was signed from.

    python3 -I apk-unsign.py <signed.apk> <out.apk>

The vault is signed with APK Signature Scheme v3 only (no v1, which would add files to the APK), with
--alignment-preserved. apksigner then pads the file entries with zeros to a 4096-byte boundary, inserts the
signing block before the central directory, and moves the central directory's offset in the end record; it
changes nothing else. Undoing exactly that gives the unsigned APK byte for byte, so its SHA-256 can be
compared with a build from source (release/verify.sh).
"""
import struct
import sys

MAGIC = b"APK Sig Block 42"


def unsign(data: bytes) -> bytes:
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 22 > len(data):
        raise ValueError("not a zip file: no end of central directory record")
    (comment_len,) = struct.unpack_from("<H", data, eocd + 20)
    if eocd + 22 + comment_len != len(data):
        raise ValueError("unexpected data after the end record")
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    if cd_offset + cd_size != eocd:
        raise ValueError("central directory doesn't end at the end record (zip64 or damaged)")
    if cd_offset < 32 or data[cd_offset - 16:cd_offset] != MAGIC:
        raise ValueError("no APK Signing Block: the APK isn't signed with v2/v3")
    (size_in_footer,) = struct.unpack_from("<Q", data, cd_offset - 24)
    start = cd_offset - size_in_footer - 8
    if start < 0 or struct.unpack_from("<Q", data, start)[0] != size_in_footer:
        raise ValueError("damaged APK Signing Block")
    entries_end = _end_of_entries(data, cd_offset, eocd)
    if entries_end > start or any(data[entries_end:start]):
        raise ValueError("unexpected bytes between the file entries and the signing block")
    end_record = bytearray(data[eocd:])
    struct.pack_into("<I", end_record, 16, entries_end)  # the central directory now follows the last entry
    return data[:entries_end] + data[cd_offset:eocd] + bytes(end_record)


def _end_of_entries(data: bytes, cd_offset: int, eocd: int) -> int:
    """Where the last file entry's data ends, from the central directory and each local header."""
    (count,) = struct.unpack_from("<H", data, eocd + 10)
    end, p = 0, cd_offset
    for _ in range(count):
        if data[p:p + 4] != b"PK\x01\x02":
            raise ValueError("damaged central directory")
        flags, = struct.unpack_from("<H", data, p + 8)
        compressed, = struct.unpack_from("<I", data, p + 20)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, p + 28)
        local, = struct.unpack_from("<I", data, p + 42)
        if data[local:local + 4] != b"PK\x03\x04":
            raise ValueError("damaged local file header")
        local_name, local_extra = struct.unpack_from("<HH", data, local + 26)
        entry_end = local + 30 + local_name + local_extra + compressed
        if flags & 0x08:  # a data descriptor follows the data
            entry_end += 16 if data[entry_end:entry_end + 4] == b"PK\x07\x08" else 12
        end = max(end, entry_end)
        p += 46 + name_len + extra_len + comment_len
    return end


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: apk-unsign.py <signed.apk> <out.apk>")
    with open(sys.argv[1], "rb") as f:
        signed = f.read()
    try:
        unsigned = unsign(signed)
    except ValueError as e:
        sys.exit(f"apk-unsign: {e}")
    with open(sys.argv[2], "wb") as f:
        f.write(unsigned)
