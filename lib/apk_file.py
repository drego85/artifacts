import os
import shutil
import hashlib
import logging
from apkInspector.headers import ZipEntry

logging.basicConfig(level=logging.WARNING)

def validateAPK(apkfile):
    # first 4 bytes APK, JAR (ZIP, XLSM): 
    # 50 4b 03 04
    header = "504b0304"
    with open(apkfile, 'rb') as file:
        byte = file.read(4)
        if not header == bytes(byte).hex():
            return False
        return True

def extractAPK(apkfile, folder):
    if not validateAPK(apkfile):
        print(f"The file {apkfile} under analysis is not an APK, I will proceed with the analysis if it is a DEX.")
        shutil.copy(apkfile, folder)
        return

    if not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)

    apk_label = os.path.splitext(os.path.basename(apkfile))[0]

    try:
        with open(apkfile, "rb") as apk_stream:
            zip_entry = ZipEntry.parse(apk_stream)
            result_code = zip_entry.extract_all(folder, apk_label)
    except Exception as exc:
        raise RuntimeError(f"apkInspector extraction failed: {exc}") from exc

    if result_code not in (0, 2, None):
        raise RuntimeError(f"apkInspector extract_all returned unexpected code {result_code}")

    extracted_files = list(os.scandir(folder))
    if not extracted_files:
        raise RuntimeError("apkInspector reported success but no files were extracted.")

    if apk_label:
        nested_dir = os.path.join(folder, apk_label)
        if os.path.isdir(nested_dir):
            for entry in os.listdir(nested_dir):
                src = os.path.join(nested_dir, entry)
                dst = os.path.join(folder, entry)
                if os.path.exists(dst):
                    os.remove(dst) if os.path.isfile(dst) else shutil.rmtree(dst)
                shutil.move(src, dst)
            shutil.rmtree(nested_dir, ignore_errors=True)

    return

        
def md5APK(apkfile):
    with open(apkfile, 'rb') as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()
