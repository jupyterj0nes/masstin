#!/usr/bin/env python3
"""Normalise a masstin timeline so runs on different machines compare equal.

The only column that legitimately differs between operating systems is
`log_filename`: it carries the absolute path of the artifact on the runner
(workspace prefix, drive letter, path separator). Everything before the
dataset directory is dropped and backslashes become slashes; every other
column is left untouched. Prints the SHA-256 of the normalised file and
writes it next to the input with a `.norm` suffix.

usage: normalize_timeline.py timeline.csv DATASET_DIR_NAME [DATASET_DIR_NAME ...]
"""
import csv, hashlib, re, sys

src = sys.argv[1]
names = sys.argv[2:]
pat = re.compile(r'^.*?(' + '|'.join(re.escape(n) for n in names) + r')')

rows = []
with open(src, encoding='utf-8', newline='') as f:
    reader = csv.reader(f)
    header = next(reader)
    idx = header.index('log_filename')
    for row in reader:
        p = row[idx].replace('\\', '/')
        row[idx] = pat.sub(r'\1', p)
        rows.append(row)

out = src + '.norm'
with open(out, 'w', encoding='utf-8', newline='') as f:
    w = csv.writer(f, lineterminator='\n')
    w.writerow(header)
    w.writerows(rows)

h = hashlib.sha256(open(out, 'rb').read()).hexdigest()
print(f'{h}  {out}  ({len(rows)} rows)')
