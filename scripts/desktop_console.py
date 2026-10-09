"""Serial acknowledgements and readiness for the actual desktop boot fixture."""

DESKTOP_MARKERS = frozenset({
    b"NORMAL_BOOT_PASS", b"WINDOW_MANAGER_PASS", b"XTERM_WINDOW_PASS",
    b"X11_KEYBOARD_PASS", b"DESKTOP_CAPTURE_READY",
})


def acknowledgement(marker):
    """Keep the completed marker out of the command's console input echo."""
    prefix, suffix = marker.rsplit(b"_", 1)
    return b"printf '%s%s\\n' " + prefix + b"_ " + suffix


def desktop_test_command():
    return (b"while ! test -f /tmp/xterm-ready; do sleep .1; done; "
            b"/bin/x11-probe --desktop && " + acknowledgement(b"DESKTOP_INPUT_READY") + b"; "
            b"while ! test -f /tmp/x11-input-pass; do sleep .1; done; " +
            acknowledgement(b"X11_KEYBOARD_PASS") + b"; " +
            acknowledgement(b"DESKTOP_CAPTURE_READY") + b"; sleep 2; " +
            acknowledgement(b"NORMAL_BOOT_PASS") + b"\n")


def desktop_complete(lines, input_sent, screenshot_ready):
    return input_sent and screenshot_ready and DESKTOP_MARKERS.issubset(lines)
