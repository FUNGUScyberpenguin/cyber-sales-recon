"""Builders for evidence the rules read. They match the shapes the sources write."""
from reconbrief.models import Tri
from reconbrief.rules import run_rules
from reconbrief.sources.common import make_evidence

D = "acme.com"


def page(host, status=200, live=True, scheme="https", title="", headers=None, wildcard_host=False, **extra):
    data = dict(scheme=scheme, error_class="ok", status=status, final_url=extra.pop("final_url", f"{scheme}://{host}/"),
                headers=headers if headers is not None else [], banners=extra.pop("banners", []),
                set_cookie_names=extra.pop("set_cookie_names", []), content_type="text/html", title=title,
                has_password_form=False, script_srcs=[], iframe_srcs=[], form_actions=[], custom_elements=[],
                certification_mentions=[], links=[], wildcard_host=wildcard_host, live=live)
    data.update(extra)
    return make_evidence("page_loader", "web_page", host, Tri.FOUND, **data)


def cert(host, **kw):
    data = dict(subject_cn=host, san=[host], expired=False, not_yet_valid=False, days_left=200, self_signed=False,
                name_matches_host=True, key_type="RSA", key_bits=2048, signature_hash="sha256")
    data.update(kw)
    return make_evidence("page_loader", "certificate", host, Tri.FOUND, **data)


def host_dns(host, addresses=("93.184.216.34",), wildcard=False, chain=None):
    return make_evidence("host_resolution", "host_dns", host, Tri.FOUND, chain=chain or [host],
                         addresses=list(addresses), error="", seen_by=["certificate_transparency"], matches_wildcard=wildcard)


def txt(kind, subject, state, *records):
    return make_evidence("dns_records", kind, subject, state, records=list(records))


def findings(evidence, domain=D):
    result, problems = run_rules(list(evidence), domain)
    assert not problems, problems
    return {f.id: f for f in result}
