"""One explicitly bounded Windows candidate, not general Windows support."""

import os
import platform
import struct
import sys

from ..trusted_workspace.reader import _local_ntfs, _normalise, _Refused
from .projection import ReportError

PROFILE_STATUS = "DEVELOPER_VALIDATED_CANDIDATE"


def fixed_profile(root):
    if sys.platform != "win32" or os.name != "nt":
        raise ReportError("PLATFORM_NOT_SUPPORTED")
    version = sys.getwindowsversion()
    if ((version.major, version.minor, version.build) != (10, 0, 26200) or
        sys.version_info[:3] != (3, 13, 2) or platform.python_implementation() != "CPython" or
        struct.calcsize("P") != 8 or platform.machine().upper() != "AMD64"):
        raise ReportError("FIXED_PROFILE_NOT_SUPPORTED")
    try:
        _local_ntfs(_normalise(root))
    except (OSError, _Refused, ValueError, TypeError):
        raise ReportError("FIXED_PROFILE_FILESYSTEM_UNSUPPORTED") from None
    return dict(profile_id="windows-10.0.26200-cpython-3.13.2-amd64-ntfs", system="Windows",
                windows_build=26200, python_version="3.13.2", architecture="AMD64", filesystem="NTFS",
                validation_status=PROFILE_STATUS)
