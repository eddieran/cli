"""
Sanitize terminal control sequences from HTTP response output.

When outputting to a TTY, malicious HTTP responses can inject terminal
escape sequences (ANSI CSI, OSC, etc.) to manipulate the terminal display,
change the window title, inject clipboard content, or worse.

This module provides sanitization that strips dangerous control characters
while preserving safe whitespace (\t, \n, \r) and legitimate color codes
added by HTTPie's own formatting/syntax highlighting.

See: https://github.com/httpie/cli/issues/1812
"""
import re

# CSI (Control Sequence Introducer) sequences: ESC [ ... <final byte>
# These control cursor movement, display attributes, etc.
# We preserve color sequences (SGR: ESC [ <params> m) since HTTPie adds those.
_CSI_RE = re.compile(
    rb'\x1b\['           # ESC [
    rb'[0-9;]*'          # parameter bytes
    rb'[^0-9;m]'         # final byte that is NOT 'm' (SGR)
)

# OSC (Operating System Command) sequences: ESC ] ... (ST | BEL)
# These can set window title, manipulate clipboard, etc.
_OSC_RE = re.compile(
    rb'\x1b\]'           # ESC ]
    rb'.*?'              # payload
    rb'(?:\x1b\\|\x07)'  # string terminator (ESC \ or BEL)
)

# Other escape sequences: ESC followed by a single character
# (e.g., ESC 7, ESC 8, ESC c for terminal reset)
# Exclude ESC [ (CSI, handled above) and ESC ] (OSC, handled above)
_OTHER_ESC_RE = re.compile(
    rb'\x1b'             # ESC
    rb'[^[\]]'           # any char except [ and ]
)

# C0 control characters that are dangerous.
# We keep: \t (0x09), \n (0x0a), \r (0x0d), \x1b (handled by regex above)
# We strip: all other C0 chars (0x00-0x08, 0x0b-0x0c, 0x0e-0x1a, 0x1c-0x1f)
# Plus DEL (0x7f)
_C0_DANGEROUS = re.compile(
    rb'[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]'
)


def sanitize_output(data: bytes) -> bytes:
    """Remove dangerous terminal control sequences from output bytes.

    Preserves:
    - Tab (\\t), newline (\\n), carriage return (\\r)
    - SGR color sequences (ESC [ ... m) used by HTTPie's syntax highlighting

    Removes:
    - CSI sequences other than SGR (cursor movement, scrolling, etc.)
    - OSC sequences (window title, clipboard manipulation, etc.)
    - Other single-character escape sequences (terminal reset, etc.)
    - Dangerous C0 control characters and DEL

    """
    data = _OSC_RE.sub(b'', data)
    data = _CSI_RE.sub(b'', data)
    data = _OTHER_ESC_RE.sub(b'', data)
    data = _C0_DANGEROUS.sub(b'', data)
    return data
