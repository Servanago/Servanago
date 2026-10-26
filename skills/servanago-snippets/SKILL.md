---
name: servanago-snippets
description: Manage named Caddyfile snippets on a ServanaGo host through MCP, and attach them to sites. Use when asked to add security headers, redirects, canned responses, request limits or compression to ServanaGo sites, or to list, change or delete a ServanaGo snippet.
---

# ServanaGo snippets over MCP

Requires ServanaGo 0.5.0 or newer.

Tools: `list_snippets`, `create_snippet`, `update_snippet`, `delete_snippet`, and `update_site` with `snippets` to attach them (see `servanago-sites`). Connection rules are in `servanago-mcp`.

## Model

A snippet is a named block of Caddyfile directives. Sites attach any number by name; they run in alphabetical order after the gate, allowlist and basic auth and before the site's own handler. `/.well-known/*` bypasses them so certificate challenges keep working.

## Tools

- `list_snippets`: name, body and the sites using each. Run it first.
- `create_snippet {name, body}`: name is lowercase letters, digits, `_` and `-`.
- `update_snippet {name, body}`: replaces the body; every site using it picks the change up at once. Check `UsedBy` from `list_snippets` and tell the user how many sites are affected.
- `delete_snippet {name}`: only if no site uses it. Detach first with `update_site` and `snippets`.

## What a body may contain

Named matchers with `respond`, `error`, `redir`, `header`, `request_header`, `request_body`, `encode`. ServanaGo refuses directives that serve, proxy or authenticate, plus `import`, env or file placeholders, extra site blocks, and directives that do nothing here such as `tls` and `log`. A rejection returns the reason; fix the body, do not work around it.

Matcher gotcha: different matcher types inside one named matcher are ANDed (a `path_regexp` plus a `path` line never matches); repeated `path` lines are ORed.

Example body:

```
@api path /api/*
header @api Cache-Control "no-store"
```
