# OVK Resource Explorer (development preview)

A responsive, dependency-free public-facing discovery interface for Open Verification Kernel. It is a **curated index** of actual repository documentation, code examples and intent templates, with descriptive search, keyboard navigation, clear evidence boundaries and copyable local development instructions.

## Local preview

Open `site/index.html` in a browser. No package installation, API key, login, or build step is necessary. For local HTTP development:

```bash
python -m http.server 8080 --directory site
# Open http://localhost:8080/
```

This is not currently a live hosted service. GitHub Pages is not enabled; deploying is a separate maintainer decision. The site performs no verification, stores no user data, and makes no GitHub API requests. It links to GitHub source files; two draft-only documents have exact candidate-commit links and are labeled as drafts. Resource search is client-side over `assets/catalog.js` (51 selected entries), **not** a full-text search over the whole repository or an evidence search API.

## Accessibility and behavior

- Responsive navigation and category filter scrolling; mobile and desktop layouts.
- Keyboard shortcut `Ctrl/⌘+K` or `/` to focus search, `Escape` to clear, `ArrowDown` to focus the first result, `Enter` to focus the top result.
- Search category, title, description, source path and topic keywords; all words must match some field. URLs preserve `q` and `category` where history access is available.
- Live result counts, explicit no-results recovery, focus indicators, reduced-motion support, semantic landmarks, and real anchors.
- Search terms are escaped via `textContent`, not interpolated into HTML. Links use full public GitHub paths and `rel="noopener noreferrer"`.

## Testing

```bash
node --check site/assets/catalog.js
node --check site/assets/app.js
python site/tests/browser_smoke.py
```

The browser smoke test runs Chromium/Playwright with local HTML/CSS/JS injection to avoid network restrictions. It checks search, filtering, keyboard, copy, responsive layout, and script errors. Use a real browser to inspect layout manually before publishing.

## Editorial and publication policy

1. Add only resources whose paths exist in the repository at their declared ref. Check both the title and description against the source; avoid invented capability maturity.
2. Link `main` resources to `main`; link unmerged draft resources to an exact commit with an explicit Development draft label. Remove or update draft index entries when their status changes.
3. The `Current release status` page is authoritative for deployment maturity; a page redesign does not certify verifiers, authorize a signed release, or address repository-ref governance.
4. The site does not display real PR/evidence results or upload source snippets. Adding such features requires an evidence-authentication and privacy review.
5. Do not activate public hosting without maintainer review of the domain, headers, privacy policy, intended public scope, and deployment provenance.
