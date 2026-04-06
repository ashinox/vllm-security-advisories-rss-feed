from dataclasses import dataclass
from datetime import datetime
from feedgen.feed import FeedGenerator

import requests


@dataclass
class SecurityAdvisory:
    ghsa_id: str
    cve_id: str
    url: str
    html_url: str
    summary: str
    description: str
    severity: str
    state: str
    published_at: datetime


def fetch_security_advisories():
    response = requests.get(
        f"https://api.github.com/repos/vllm-project/vllm/security-advisories"
    )
    response.raise_for_status()

    security_advisories = []
    for sa in response.json():
        security_advisories.append(
            SecurityAdvisory(
                ghsa_id=sa.get("ghsa_id"),
                cve_id=sa.get("cve_id"),
                url=sa.get("url"),
                html_url=sa.get("html_url"),
                summary=sa.get("summary"),
                description=sa.get("description"),
                severity=sa.get("severity"),
                state=sa.get("state"),
                published_at=datetime.fromisoformat(
                    sa.get("published_at").replace("Z", "+00:00")
                ),
            )
        )
    return security_advisories


def generate_rss_feed(security_advisories: list[SecurityAdvisory]):
    fg = FeedGenerator()

    fg.title("vLLM Security Advisories")
    fg.link(
        href="https://tar-xzvff.github.io/vllm-security-advisories-rss-feed/rss.xml",
        rel="self",
    )
    fg.description("vLLM Security Advisories")

    for sa in security_advisories:
        fe = fg.add_entry()
        fe.id(sa.ghsa_id)
        fe.title(f"[{sa.severity}] {sa.summary}")
        fe.published(sa.published_at)
        fe.link(href=sa.html_url)

    fg.rss_file("rss.xml")


if __name__ == "__main__":
    _security_advisories = fetch_security_advisories()
    generate_rss_feed(_security_advisories)
