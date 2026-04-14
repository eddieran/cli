"""
Tests for terminal escape sequence sanitization.

See: https://github.com/httpie/cli/issues/1812
"""
import pytest
import responses

from httpie.output.sanitize import sanitize_output
from .utils import http, MockEnvironment, DUMMY_URL


class TestSanitizeFunction:
    """Unit tests for the sanitize_output() function."""

    def test_plain_text_unchanged(self):
        data = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello'
        assert sanitize_output(data) == data

    def test_preserves_tab_newline_cr(self):
        data = b'line1\tvalue\nline2\r\n'
        assert sanitize_output(data) == data

    def test_preserves_sgr_color_codes(self):
        # SGR sequences (ESC [ ... m) are used by HTTPie for syntax highlighting
        data = b'\x1b[31mred text\x1b[0m normal'
        assert sanitize_output(data) == data

    def test_preserves_complex_sgr(self):
        data = b'\x1b[38;5;245mcolored\x1b[39m'
        assert sanitize_output(data) == data

    def test_strips_osc_title_set(self):
        # OSC sequence to set terminal title
        data = b'before\x1b]0;evil title\x07after'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_osc_clipboard(self):
        # OSC 52 clipboard manipulation
        data = b'before\x1b]52;c;ZXZpbA==\x07after'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_osc_with_st_terminator(self):
        # OSC terminated with ST (ESC \)
        data = b'before\x1b]0;evil\x1b\\after'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_csi_cursor_movement(self):
        # CSI sequence for cursor movement (ESC [ ... H)
        data = b'before\x1b[2;1Hafter'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_csi_erase_display(self):
        # CSI sequence to erase display (ESC [ 2 J)
        data = b'before\x1b[2Jafter'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_csi_scroll(self):
        # CSI scroll up (ESC [ ... S)
        data = b'before\x1b[5Safter'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_dangerous_c0(self):
        # BEL (0x07), BS (0x08), VT (0x0b), FF (0x0c), etc.
        data = b'before\x07\x08\x0b\x0cafter'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_del(self):
        data = b'before\x7fafter'
        assert sanitize_output(data) == b'beforeafter'

    def test_strips_esc_c_terminal_reset(self):
        # ESC c = full terminal reset
        data = b'before\x1bcafter'
        assert sanitize_output(data) == b'beforeafter'

    def test_combined_attack_payload(self):
        # Simulate a realistic attack: set title + inject clipboard + cursor move
        payload = (
            b'HTTP/1.1 200 OK\r\n'
            b'X-Evil: \x1b]0;pwned\x07'     # set title
            b'\x1b]52;c;ZXZpbA==\x07'       # clipboard
            b'\x1b[2J'                       # clear screen
            b'\x1b[1;1H'                     # cursor home
            b'fake content'
            b'\r\n\r\n'
            b'body'
        )
        result = sanitize_output(payload)
        assert b'\x1b]' not in result       # no OSC sequences
        assert b'pwned' not in result
        assert b'ZXZpbA==' not in result
        assert b'body' in result
        assert b'fake content' in result     # plain text preserved


class TestSanitizationInOutput:
    """Integration tests verifying sanitization is applied during output."""

    @responses.activate
    def test_tty_output_sanitizes_response_headers(self):
        """Escape sequences in response headers are stripped for TTY output."""
        responses.add(
            method=responses.GET,
            url=DUMMY_URL,
            body=b'ok',
            headers={'X-Evil': '\x1b]0;pwned\x07'},
        )
        env = MockEnvironment(stdout_isatty=True)
        r = http('--print=h', DUMMY_URL, env=env)
        assert 'pwned' not in r
        assert '\x1b]' not in r

    @responses.activate
    def test_tty_output_sanitizes_response_body(self):
        """Escape sequences in response body are stripped for TTY output."""
        responses.add(
            method=responses.GET,
            url=DUMMY_URL,
            body=b'before\x1b]0;evil title\x07after',
            content_type='text/plain',
        )
        env = MockEnvironment(stdout_isatty=True)
        r = http('--print=b', DUMMY_URL, env=env)
        assert 'evil title' not in r
        assert 'beforeafter' in r

    @responses.activate
    def test_pipe_output_preserves_escape_sequences(self):
        """Escape sequences are NOT stripped when output is piped (not a TTY)."""
        responses.add(
            method=responses.GET,
            url=DUMMY_URL,
            body=b'before\x1b]0;title\x07after',
            content_type='text/plain',
        )
        env = MockEnvironment(stdout_isatty=False)
        r = http('--print=b', DUMMY_URL, env=env)
        # When piped, raw data should be preserved (RawStream writes bytes)
        raw = r if isinstance(r, bytes) else r.encode()
        assert b'before' in raw
        assert b'\x1b]' in raw

    @responses.activate
    def test_tty_output_preserves_sgr_colors(self):
        """HTTPie's own color codes (SGR) are preserved during sanitization."""
        responses.add(
            method=responses.GET,
            url=DUMMY_URL,
            body=b'{"key": "value"}',
            content_type='application/json',
        )
        env = MockEnvironment(stdout_isatty=True, colors=256)
        r = http('--pretty=colors', '--print=b', DUMMY_URL, env=env)
        # Colorized output should contain color codes
        assert '\x1b[' in r

    @responses.activate
    def test_tty_strips_csi_cursor_in_body(self):
        """CSI cursor-movement sequences in response body are stripped for TTY."""
        responses.add(
            method=responses.GET,
            url=DUMMY_URL,
            body=b'line1\x1b[2;1Hinjected',
            content_type='text/plain',
        )
        env = MockEnvironment(stdout_isatty=True)
        r = http('--print=b', DUMMY_URL, env=env)
        assert '\x1b[2;1H' not in r
        assert 'line1' in r
        assert 'injected' in r
