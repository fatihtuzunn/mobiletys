import os
import hashlib

def get_file_info(file_path):
    info = {
        "file_name": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path),
    }

    with open(file_path, "rb") as f:
        data = f.read()
        info["md5"] = hashlib.md5(data).hexdigest()
        info["sha1"] = hashlib.sha1(data).hexdigest()
        info["sha256"] = hashlib.sha256(data).hexdigest()

    return info
