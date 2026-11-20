"""Evidence uploads. Nothing the user sends decides where or how a file is stored."""
import secrets
from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename

# extension -> (stored extension, MIME type we will serve, allowed file signatures)
ALLOWED_TYPES = {
    "pdf": ("pdf", "application/pdf", (b"%PDF-",)),
    "png": ("png", "image/png", (b"\x89PNG\r\n\x1a\n",)),
    "jpg": ("jpg", "image/jpeg", (b"\xff\xd8\xff",)),
    "jpeg": ("jpg", "image/jpeg", (b"\xff\xd8\xff",)),
}


class UploadError(ValueError):
    """The file was refused. The message is safe to show to the user."""


def save_upload(file_storage) -> dict:
    """Validate an uploaded file and store it under a random name.

    Checks, in order: the extension is on the allow-list, the size is within
    the limit, and the first bytes match the claimed type. Returns the fields
    for an Attachment row.
    """
    original = secure_filename(file_storage.filename or "")[:120]
    extension = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if extension not in ALLOWED_TYPES:
        raise UploadError("Only PDF, PNG and JPG files can be attached.")

    limit = current_app.config["MAX_UPLOAD_BYTES"]
    data = file_storage.stream.read(limit + 1)
    if len(data) > limit:
        raise UploadError(f"The file is larger than {limit // (1024 * 1024)} MB.")
    if not data:
        raise UploadError("The file is empty.")

    stored_extension, mime_type, signatures = ALLOWED_TYPES[extension]
    if not data.startswith(signatures):
        raise UploadError("The file's contents do not match its type.")

    stored_name = f"{secrets.token_hex(16)}.{stored_extension}"
    folder = Path(current_app.config["UPLOAD_FOLDER"])
    folder.mkdir(parents=True, exist_ok=True)
    (folder / stored_name).write_bytes(data)

    return {
        "original_name": original,
        "stored_name": stored_name,
        "mime_type": mime_type,
        "size": len(data),
    }
