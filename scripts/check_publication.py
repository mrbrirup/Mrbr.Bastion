"""Check the actual Git publication set. Python 3.11+, standard library only.

Secret scanning and human screenshot review are separate required checks. This
gate verifies exclusions, links, image structure/metadata and reviewed hashes.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import urllib.parse
import zlib


def image_check(path: Path) -> None:
    data = path.read_bytes()
    if path.suffix.lower() == '.png':
        if data[:8] != bytes.fromhex('89504e470d0a1a0a'):
            raise ValueError('PNG extension does not match file content')
        position, compressed, ended = 8, bytearray(), False
        while position + 12 <= len(data):
            length = struct.unpack('>I', data[position:position+4])[0]
            kind = data[position+4:position+8]
            if length > len(data) - position - 12:
                raise ValueError('Truncated PNG chunk')
            body = data[position+8:position+8+length]
            crc = struct.unpack('>I', data[position+8+length:position+12+length])[0]
            if zlib.crc32(kind+body) != crc:
                raise ValueError('PNG checksum failed')
            if kind in (b'tEXt', b'iTXt', b'zTXt', b'eXIf'):
                raise ValueError('Text/EXIF metadata requires removal or withholding and renewed review')
            if kind == b'IDAT':
                compressed.extend(body)
            position += length + 12
            if kind == b'IEND':
                ended = True
                break
        if not ended or position != len(data) or not zlib.decompress(compressed):
            raise ValueError('Incomplete PNG or appended data')
    elif path.suffix.lower() in ('.jpg', '.jpeg'):
        if data[:2] != bytes.fromhex('ffd8') or data[-2:] != bytes.fromhex('ffd9'):
            raise ValueError('Invalid JPEG or extension mismatch')
        position = 2
        while position < len(data):
            if data[position] != 0xff:
                raise ValueError('Invalid JPEG marker')
            while position < len(data) and data[position] == 0xff:
                position += 1
            marker = data[position]
            position += 1
            if marker in (0xda, 0xd9):
                break  # Entropy-coded image data; the trailing EOI was checked above.
            if 0xe1 <= marker <= 0xef or marker == 0xfe:
                raise ValueError('Application/comment metadata requires withholding and renewed review')
            length = struct.unpack('>H', data[position:position+2])[0]
            if length < 2 or position + length > len(data):
                raise ValueError('Invalid JPEG segment length')
            position += length
    else:
        raise ValueError('Unreviewed image format')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-untracked', action='store_true', help='Also check non-ignored untracked files during preparation')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    command = ['git', 'ls-files', '-z', '--cached']
    if args.include_untracked:
        command += ['--others', '--exclude-standard']
    raw = subprocess.check_output(command, cwd=root)
    files = sorted(set(x.decode('utf-8') for x in raw.split(b'\0') if x))
    if not files:
        raise RuntimeError('No versioned candidate files; stage the candidate or use --include-untracked')
    public = set(files)
    review = json.loads((root/'release/screenshot-review.json').read_text(encoding='utf-8'))
    reviewed = {item['path']: item for item in review['included']}
    withheld = {item['path'] for item in review['withheld']}
    denied_roots = {'.git', '.vs', '.idea', '.agents', '.codex', '.aws', '.nuget', 'docs', 'tmp', 'artifacts', 'data', 'keys'}
    denied_suffixes = {'.pem', '.key', '.pfx', '.p12', '.snk', '.db', '.sqlite', '.sqlite3', '.bastion-archive', '.dll', '.exe', '.so', '.dylib', '.trx', '.log', '.user', '.suo', '.zip', '.tar', '.gz'}
    failures, image_count, project_count = [], 0, 0
    for name in files:
        relative = PurePosixPath(name)
        path = root/name
        if relative.is_absolute() or '..' in relative.parts or path.is_symlink() or not path.resolve().is_relative_to(root):
            failures.append(f'{name}: unsafe path')
            continue
        if not path.is_file():
            failures.append(f'{name}: missing file')
            continue
        lower = name.lower()
        if (relative.parts[0].lower() in denied_roots or any(part.lower() in {'bin', 'obj'} for part in relative.parts)
                or path.suffix.lower() in denied_suffixes or lower.endswith(('.local.json', '.db-wal', '.db-shm', '.writer.lock'))
                or path.name.startswith('.env') and path.name != '.env.example' or name in withheld):
            failures.append(f'{name}: private/generated file in public set')
        if path.stat().st_size > 8 * 1024 * 1024:
            failures.append(f'{name}: exceeds reviewed public-file size limit')
        if path.suffix == '.csproj':
            project_count += 1
            if (relative.parent/'packages.lock.json').as_posix() not in public:
                failures.append(f'{name}: dependency lock file is absent from public set')
        if path.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}:
            image_count += 1
            item = reviewed.get(name)
            if item is None or item.get('sha256') != hashlib.sha256(path.read_bytes()).hexdigest():
                failures.append(f'{name}: missing or stale human screenshot review')
            try:
                image_check(path)
            except (ValueError, IndexError, struct.error, zlib.error) as error:
                failures.append(f'{name}: {error}')
        if path.suffix.lower() == '.md':
            text = path.read_text(encoding='utf-8-sig')
            text = re.sub(r'(?ms)^```.*?^```[^\n]*', '', text)
            for link in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text):
                link = link.strip().split(' "', 1)[0].strip('<>')
                parsed = urllib.parse.urlsplit(link)
                if parsed.scheme or not parsed.path:
                    continue
                target = (path.parent/urllib.parse.unquote(parsed.path)).resolve()
                if not target.is_relative_to(root):
                    failures.append(f'{name}: link escapes checkout')
                    continue
                target_name = target.relative_to(root).as_posix()
                if target.is_dir():
                    exists = any(x.startswith(target_name.rstrip('/')+'/') for x in files)
                else:
                    exists = target_name in public
                if not exists:
                    failures.append(f'{name}: link target not published: {parsed.path}')
    for name in reviewed:
        if name not in public:
            failures.append(f'{name}: stale included-image review entry')
    canaries = ['docs/research.md', 'tmp/private.txt', 'keys/node-private.pem', 'data/outbox.db',
                'deployment.bastion.local.json', 'artifacts/test-results/core.trx', *withheld]
    ignored = subprocess.run(['git', 'check-ignore', '--no-index', '-z', '--stdin'],
                             input=('\0'.join(canaries)+'\0').encode('utf-8'), cwd=root, capture_output=True)
    if not set(canaries).issubset({x.decode('utf-8') for x in ignored.stdout.split(b'\0') if x}):
        failures.append('Required private/generated paths are not all ignored')
    print(json.dumps(dict(candidateFiles=len(files), projects=project_count, reviewedScreenshots=image_count,
                          withheldScreenshots=len(withheld), failures=failures), indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
