"""Export the FastAPI contract and a self-contained, offline HTTP reference."""

import json
from html import escape
from pathlib import Path

from ales_server import create_app
from ales_server.auth import EXEMPT_PATHS

OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "api"


def pretty(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)


def code(value: object) -> str:
    return "<pre>" + escape(pretty(value)) + "</pre>"


def main() -> None:
    schema = create_app("sqlite://", env={}).openapi()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "openapi.json").write_text(pretty(schema) + "\n", encoding="utf-8", newline="\n")

    title = escape(schema["info"]["title"])
    sections = [
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">',
        f"<title>{title} HTTP reference</title>",
        (
            "<style>body{font:1rem/1.55 system-ui;max-width:72rem;margin:auto;padding:1.5rem;color:#18283a}"
            "a{color:#18589a} pre{overflow:auto;background:#f1f4f7;padding:1rem} summary{cursor:pointer}"
            "section{border-top:1px solid #ccd4dc;margin-top:2rem} h2{overflow-wrap:anywhere}</style>"
        ),
        (
            f"<h1>{title}</h1><p>HTTP reference for server {escape(schema['info']['version'])}. "
            '<a href="openapi.json">Download OpenAPI JSON</a>.</p>'
        ),
        (
            "<p>Send your tenant's service credential in the Authorization: Bearer header. "
            "Request bodies contain lineage and authority metadata. The application retains the payload. "
            "Check the decision inside a successful release response before executing its action.</p>"
        ),
        '<nav aria-label="Endpoints"><ul>',
    ]
    operations = []
    for path, methods in sorted(schema["paths"].items()):
        for method, operation in methods.items():
            label = escape(f"{method.upper()} {path}")
            anchor = escape(operation["operationId"], quote=True)
            sections.append(f'<li><a href="#{anchor}">{label}</a></li>')
            auth = "Public health probe" if path in EXEMPT_PATHS else "Tenant credential required"
            operations.extend(
                [
                    f'<section id="{anchor}"><h2>{label}</h2><p>{escape(operation["summary"])}. {auth}.</p>',
                    f"<p>{escape(operation.get('description', ''))}</p>",
                ]
            )
            for key, heading in [
                ("parameters", "Parameters"),
                ("requestBody", "Request body"),
                ("responses", "Responses"),
            ]:
                if key in operation:
                    operations.append(
                        f"<details><summary>{heading}</summary>{code(operation[key])}</details>"
                    )
            operations.append("</section>")
    sections.extend(["</ul></nav>", *operations, "<h2>Schema definitions</h2>"])
    for name, definition in sorted(schema.get("components", {}).get("schemas", {}).items()):
        sections.append(f"<details><summary>{escape(name)}</summary>{code(definition)}</details>")
    sections.append("</html>")
    (OUTPUT / "index.html").write_text("\n".join(sections) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
