"""Centralized, dependency-free terminal presentation."""
import sys

class Console:
    def __init__(self, *, no_color=False, stream=None, verbose=False, debug=False):
        self.stream = stream or sys.stdout
        self.verbose = verbose
        self.debug = debug
        enabled = not no_color and getattr(self.stream, "isatty", lambda: False)()
        self.colors = enabled
        names = ("green", "red", "yellow", "cyan", "blue", "navy", "steel", "dim", "reset")
        self.c = {x: "" for x in names}
        if enabled:
            self.c.update({"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m",
                           "cyan": "\033[36m", "blue": "\033[38;5;33m", "navy": "\033[38;5;24m",
                           "steel": "\033[38;5;67m",
                           "dim": "\033[2m", "reset": "\033[0m"})

    def paint(self, text, color=None):
        return f"{self.c.get(color, '')}{text}{self.c['reset'] if color else ''}"

    def line(self, text=""):
        print(text, file=self.stream, flush=True)

    def activity(self, text):
        self.line(self.paint(f"[ * ] {text}", "blue"))

    def complete(self, text, state="PASS"):
        marker = "[ + ]" if state == "PASS" else ("[ ! ]" if state in {"WARNING", "PARTIAL"} else "[ - ]")
        color = "green" if state == "PASS" else ("yellow" if state in {"WARNING", "PARTIAL"} else "dim")
        self.line(self.paint(f"{marker} {text}", color))

    def heading(self, text):
        self.line(self.paint(text, "cyan"))

    def status(self, text, state=None):
        palette = {"PASS": "green", "VALID": "green", "CORROBORATED": "green",
                   "FAILED": "red", "INVALID": "red", "DISAGREEMENT": "yellow",
                   "SINGLE-SOURCE": "yellow", "PARTIAL": "yellow",
                   "UNAVAILABLE": "yellow", "NOT AVAILABLE": "yellow"}
        self.line(self.paint(text, palette.get(str(state or "").upper())))

    def debug_line(self, text):
        if self.debug: self.line(self.paint(f"[DEBUG] {text}", "dim"))

    def banner(self, text):
        """Render the packaged artwork without changing its text."""
        colors = ("navy", "navy", "blue", "blue", "steel")
        for index, line in enumerate(text.splitlines()):
            self.line(self.paint(line, colors[index % len(colors)] if self.colors else None))
