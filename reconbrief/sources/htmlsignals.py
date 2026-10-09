"""Pull the signals the rules need out of one HTML page. Standard library only."""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

MAX_LINKS = 300
MAX_TEXT = 200_000


@dataclass
class PageSignals:
    title: str = ""
    og_site_name: str = ""
    generator: str = ""
    has_password_form: bool = False
    form_actions: list[str] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    iframe_srcs: list[str] = field(default_factory=list)
    icon_hrefs: list[str] = field(default_factory=list)
    custom_elements: list[str] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)  # {"href": absolute url, "text": link text}
    text: str = ""  # visible text, scripts and styles removed


class _Parser(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.s = PageSignals()
        self._in_title = False
        self._skip = 0
        self._link: dict | None = None
        self._text: list[str] = []
        self._size = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        s = self.s
        if "-" in tag and tag not in s.custom_elements and len(s.custom_elements) < 40:
            s.custom_elements.append(tag)
        if tag == "title":
            self._in_title = True
        elif tag in ("script", "style", "noscript"):
            self._skip += 1
            if tag == "script" and a.get("src"):
                s.script_srcs.append(urljoin(self.base, a["src"]))
        elif tag == "iframe" and a.get("src"):
            s.iframe_srcs.append(urljoin(self.base, a["src"]))
        elif tag == "input" and a.get("type", "").lower() == "password":
            s.has_password_form = True
        elif tag == "form" and a.get("action"):
            s.form_actions.append(urljoin(self.base, a["action"]))
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name == "og:site_name" and not s.og_site_name:
                s.og_site_name = a.get("content", "").strip()
            elif name == "generator" and not s.generator:
                s.generator = a.get("content", "").strip()
        elif tag == "link" and "icon" in a.get("rel", "").lower():
            if a.get("href"):
                s.icon_hrefs.append(urljoin(self.base, a["href"]))
        elif tag == "a" and a.get("href") and len(s.links) < MAX_LINKS:
            self._link = {"href": urljoin(self.base, a["href"]), "text": ""}
            s.links.append(self._link)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1
        elif tag == "a":
            self._link = None

    def handle_data(self, data):
        if self._in_title:
            self.s.title += data
        if self._skip:
            return
        if self._link is not None and len(self._link["text"]) < 200:
            self._link["text"] += data
        if self._size < MAX_TEXT:
            self._text.append(data)
            self._size += len(data)


def parse_html(body: bytes, base_url: str, charset: str = "utf-8") -> PageSignals:
    parser = _Parser(base_url)
    try:
        parser.feed(body.decode(charset or "utf-8", "replace"))
        parser.close()
    except Exception:  # broken markup yields whatever was read before the error
        pass
    s = parser.s
    s.title = " ".join(s.title.split())
    s.text = " ".join(" ".join(parser._text).split())
    for link in s.links:
        link["text"] = " ".join(link["text"].split())
    return s
