import exifread
import numpy as np
from PIL import Image

def calculate_entropy(data):
    """Helper function to calculate Shannon entropy."""
    if not isinstance(data, np.ndarray):
        # If data is not a numpy array, convert it from bytes
        data = np.frombuffer(data, dtype=np.uint8)

    if data.size == 0:
        return 0.0

    counts = np.bincount(data, minlength=256)
    probabilities = counts[counts > 0] / data.size
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

def analyze_image(file_stream):
    """
    对图像文件进行深度分析
    Performs a deep analysis of an image file.

    :param file_stream: A file-like object (stream) of the image file.
    :return: A tuple containing a list of findings and a dictionary of metadata.
    """
    findings = []
    metadata = {}

    try:
        file_stream.seek(0)
        # 1. EXIF Metadata using exifread
        try:
            exif_tags = exifread.process_file(file_stream, details=True, strict=False)
            if exif_tags:
                metadata['EXIF'] = {}
                for tag, value in exif_tags.items():
                    if tag not in ('JPEGThumbnail', 'TIFFThumbnail'): # Exclude thumbnails
                        try:
                            metadata['EXIF'][tag] = str(value)
                        except Exception:
                            metadata['EXIF'][tag] = repr(value)
        except Exception as e:
            # This can fail on images without EXIF data, which is fine.
            pass

        file_stream.seek(0)
        # 2. Analysis using Pillow
        with Image.open(file_stream) as img:
            # General image info
            metadata['General'] = {
                "Format": img.format,
                "Mode": img.mode,
                "Size": f"{img.width}x{img.height}"
            }

            # Other metadata (XMP, etc.)
            for key, value in img.info.items():
                if key != 'exif': # Already handled by exifread which is more thorough
                    try:
                        metadata[key.upper()] = str(value)
                    except Exception:
                         metadata[key.upper()] = repr(value)

            # 3. LSB Steganography Analysis
            if img.mode in ('RGB', 'RGBA'):
                # Convert to numpy array
                np_img = np.array(img)

                # Get the LSB plane for each channel
                lsb_plane_r = (np_img[:, :, 0] & 1) * 255
                lsb_plane_g = (np_img[:, :, 1] & 1) * 255
                lsb_plane_b = (np_img[:, :, 2] & 1) * 255

                # Calculate entropy of each LSB plane
                entropy_r = calculate_entropy(lsb_plane_r.flatten())
                entropy_g = calculate_entropy(lsb_plane_g.flatten())
                entropy_b = calculate_entropy(lsb_plane_b.flatten())

                avg_entropy = (entropy_r + entropy_g + entropy_b) / 3

                metadata['LSB_Analysis'] = {
                    "Red_Channel_Entropy": round(entropy_r, 4),
                    "Green_Channel_Entropy": round(entropy_g, 4),
                    "Blue_Channel_Entropy": round(entropy_b, 4),
                    "Average_Entropy": round(avg_entropy, 4)
                }

                # High entropy in LSB plane is a strong indicator of steganography
                if avg_entropy > 7.0: # Threshold for high entropy can be tuned
                    findings.append({
                        "type": "Potential LSB Steganography",
                        "severity": "WARNING",
                        "description": f"The average entropy of the Least Significant Bit (LSB) planes is unusually high ({avg_entropy:.4f}).",
                        "hint": "High entropy in LSB planes can indicate the presence of hidden data. Consider using a steganography tool to extract it."
                    })

    except Exception as e:
        findings.append({
            "type": "Image Analysis Error",
            "severity": "ERROR",
            "description": f"An unexpected error occurred during image analysis: {str(e)}",
        })

    return findings, metadata
