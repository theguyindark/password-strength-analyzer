import os
import hashlib
import json

restrict_dir = 'Restrict'
hashes = {}

for fname in os.listdir(restrict_dir):
    fpath = os.path.join(restrict_dir, fname)
    if os.path.isfile(fpath):
        with open(fpath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        hashes[fname] = file_hash

with open(os.path.join(restrict_dir, 'hashes.json'), 'w') as f:
    json.dump(hashes, f, indent=2)

print(f"Hashes for all files in '{restrict_dir}' have been written to '{restrict_dir}/hashes.json'.")