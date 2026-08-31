"""Centralized, dependency-free terminal presentation."""
import sys

class Console:
    def __init__(self, *, no_color=False, stream=None, verbose=False, debug=False):
        self.stream = stream or sys.stdout
        self.verbose = verbose
        self.debug = debug
        enabled = not no_color and getattr(self.stream, "isatty", lambda: False)()
        self.colors = enabled
        names = ("green", "red", "yellow", "orange", "cyan", "blue", "navy", "steel", "dim", "reset")
        self.c = {x: "" for x in names}
        if enabled:
            self.c.update({"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m",
                           "cyan": "\033[36m", "blue": "\033[38;5;33m", "navy": "\033[38;5;24m",
                           "steel": "\033[38;5;67m", "orange": "\033[38;5;208m",
                           "dim": "\033[2m", "reset": "\033[0m"})

    def paint(self, text, color=None):
        return f"{self.c.get(color, '')}{text}{self.c['reset'] if color else ''}"

    def highlight_secret(self, text):
        """Highlight an explicitly recovered target secret, when interactive."""
        return self.paint(text, "orange")

    def highlight_admin(self, text):
        """Highlight explicit administrative-access evidence, when interactive."""
        return self.paint(text, "orange")

    def highlight_control(self, text):
        """Highlight an explicit direct-control ACL primitive, when interactive."""
        return self.paint(text, "orange")

    def finding_title(self, text):
        """Render a finding headline with the consistent finding style."""
        return self.paint(text, "yellow")

    def line(self, text=""):
        print(text, file=self.stream, flush=True)

    def activity(self, text):
        self.line(self.paint(f"[ * ] {text}", "blue"))

    def complete(self, text, state="PASS"):
        marker = "[ + ]" if state == "PASS" else ("[ ! ]" if state in {"WARNING", "PARTIAL"} else "[ - ]")
        color = "green" if state == "PASS" else ("yellow" if state in {"WARNING", "PARTIAL"} else "dim")
        self.line(self.paint(f"{marker} {text}", color))

    @staticmethod
    def field(label, value, width=19, leader="........"):
        """Return a deterministic label/leader/value line.

        Keeping alignment here means terminal color escapes never become part
        of the padding calculation: callers color the completed line.
        """
        return f"  {label:<{width}} {leader} {value}"

    def heading(self, text):
        self.line(self.paint(text, "cyan"))

    def category_header(self, category):
        """Print one deliberate separator line before a findings category."""
        self.line()
        self.heading(f"------------[ {category} ]------------")

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
        artwork = text.splitlines()
        for index, line in enumerate(artwork):
            self.line(self.paint(line, colors[index % len(colors)] if self.colors else None))
        width = max((len(line) for line in artwork), default=0)
        handle = "@Evilhaxxor"
        self.line(self.paint(handle.center(width), "steel" if self.colors else None))
