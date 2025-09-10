import zipfile
import zlib

def analyze_zip(file_stream):
    """
    对ZIP文件进行深度分析
    Performs a deep analysis of a ZIP file.

    :param file_stream: A file-like object (stream) of the ZIP file.
    :return: A list of findings (dictionaries).
    """
    findings = []
    try:
        # Rewind the stream just in case
        file_stream.seek(0)
        with zipfile.ZipFile(file_stream, 'r') as zf:
            # 1. 提取全局注释 (Extract global comment)
            if zf.comment:
                findings.append({
                    "type": "ZIP Global Comment",
                    "severity": "INFO",
                    "description": "The ZIP archive contains a global comment.",
                    "value": zf.comment.decode('utf-8', 'ignore')
                })

            # 2. 遍历文件进行分析 (Iterate through files for analysis)
            for info in zf.infolist():
                # 提取文件注释 (Extract per-file comment)
                if info.comment:
                    findings.append({
                        "type": "ZIP File Comment",
                        "severity": "INFO",
                        "description": f"The file '{info.filename}' within the ZIP contains a comment.",
                        "value": info.comment.decode('utf-8', 'ignore')
                    })

                # CRC 校验 (CRC Check)
                try:
                    # 读取文件数据但不解压
                    file_data = zf.read(info.filename)
                    calculated_crc = zlib.crc32(file_data)

                    # zipfile provides the CRC from the central directory, which is authoritative
                    if calculated_crc != info.CRC:
                        findings.append({
                            "type": "CRC Mismatch",
                            "severity": "CRITICAL",
                            "description": f"CRC mismatch for file '{info.filename}'. Stored CRC: {info.CRC}, Calculated CRC: {calculated_crc}.",
                            "hint": "This file may be corrupt, or this could be a sign of intentional data tampering."
                        })
                except Exception as e:
                    # Could fail for encrypted files if password is not provided
                    pass

                # 伪加密检测 (Pseudo-encryption detection)
                # Bit 0 of flag_bits is the encryption flag.
                is_encrypted = (info.flag_bits & 0x1) == 0x1
                # True ZIP encryption zeros out the CRC in the local header.
                # If the encryption flag is set but the CRC is non-zero, it's likely pseudo-encrypted.
                # This check is a common heuristic.
                if is_encrypted and info.CRC != 0:
                    findings.append({
                        "type": "Potential Pseudo-encryption",
                        "severity": "WARNING",
                        "description": f"File '{info.filename}' is flagged as encrypted, but its header contains a CRC value.",
                        "hint": "This is a strong indicator of pseudo-encryption. Try unzipping with a tool that ignores the encryption flag."
                    })

    except zipfile.BadZipFile:
        findings.append({
            "type": "Invalid ZIP File",
            "severity": "CRITICAL",
            "description": "The uploaded file is not a valid ZIP archive, despite its type.",
        })
    except Exception as e:
        findings.append({
            "type": "ZIP Analysis Error",
            "severity": "ERROR",
            "description": f"An unexpected error occurred during ZIP analysis: {str(e)}",
        })

    return findings
