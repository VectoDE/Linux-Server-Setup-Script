# Website

The website explains lss as a film that plays while you scroll: every scene sticks to the screen while its lines
appear, its list rolls past or its items change, with a caption at the bottom. It is one static page on GitHub
Pages, built from the repository on every deploy.

## What it is built from

`scripts/build-site.sh` writes the page and reads everything it shows from the repository:

| On the page                           | Source                                                                   |
| ------------------------------------- | ------------------------------------------------------------------------ |
| One scene per module group            | `MOD_NAME`, `MOD_GROUP`, `MOD_DESCRIPTION`, `MOD_CONFLICTS` and `MOD_OPTIONS` of every module (sourced in a subshell, like `lss info`) |
| The order of an example run           | `MOD_REQUIRES`                                                           |
| Profiles                              | `profiles/*.conf` (`# Profile:` line and `LSS_MODULES`)                  |
| Guard time and thresholds             | the defaults in `MOD_OPTIONS` of `guard`                                 |
| `lss --help`                          | the `usage` function of `lss`                                            |
| The menu                              | `ui_menu` in `lib/ui.sh`                                                 |
| Supported systems, requirements       | `data/systems.conf`                                                      |
| Version                               | `VERSION`                                                                |

A new module, group or profile is on the site with the next deploy; nobody edits the page. A group the generator
does not know yet gets a scene with a plain caption after the known groups. The captions of the known groups, the
security model and the verified install are written in the generator.

`data/systems.conf` is also the source of the tables "Supported systems" and "System requirements" in the README:
`scripts/build-site.sh --check` (part of every build, so part of CI) fails when they say something else. Change
both together.

## Build and preview

```bash
scripts/build-site.sh _site            # writes _site/index.html, film.js, favicon.svg and robots.txt
python3 -m http.server -d _site 8000   # any static server will do
```

`_site/` is not committed. The page is generated in the Pages workflow (`.github/workflows/pages.yml`), so it
cannot fall behind the modules, and a pull request shows the result of its own changes.

## Motion, keyboard and screen readers

Every word of every scene is in the HTML from the start. `site/film.js` only moves and marks it: it sets the scene
counter, shows lines, rolls the stage and highlights the current item. What moves while you scroll:

| Scene                  | Motion                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------- |
| Opening                | The title steps back and shrinks; the counts of modules, groups, profiles and tested systems run up from 0 once after loading |
| Every scene            | The words of the heading rise out of their masks as it scrolls in; the caption comes in word by word (opacity and blur) |
| A run                  | Log lines appear one by one, the newest marked, and the log rolls like a terminal         |
| Profiles, menu         | One profile or menu item at a time                                                         |
| Module groups          | The list rolls past and the current module is marked                                       |
| Run to last group      | Packets drifting across the screen leave their lines in random order and close into a shield with "lss" cut out |
| Guard                  | A scan line sweeps over the shield                                                         |
| After the guard        | The field fades out and stops drawing                                                      |

The field is a 2D canvas behind the text, drawn by `film.js` without a library. It starts after the page has
loaded, stops in hidden tabs and once it has faded out, and draws at most at 1.5 times the CSS resolution. On
screens narrower than 900 px the shield sits behind the text and is drawn at half the strength. The scatter of the
packets comes from a fixed seed, so the page looks the same on every visit. The heading masks use CSS
scroll-driven animations (`animation-timeline: view()`) where the browser has them; elsewhere `film.js` raises them
when the heading comes into view, and without the script they stay where they are. Scrolling is the browser's own:
nothing takes over the wheel, keys, find in page or anchors. The film needs motion allowed
(`prefers-reduced-motion: no-preference`), scripting and a screen at least 30rem tall. Otherwise the same scenes
are a still sequence of full-screen frames, with nothing hidden.

The chapter list in the header jumps to every scene, a skip link leads to the film, and focus is always visible.
Decoration (scene numbers on the splice line, the counter, the progress bar) is hidden from screen readers; the
headings, captions, lists and tables are plain HTML.

Colour has one meaning: yellow marks what lss is doing right now, red what it refuses or what failed. The palette
is checked against WCAG AA in light and dark mode. The fonts are the system's own monospace and sans-serif.

## Content Security Policy and headers

The page loads nothing from other servers: no fonts, no analytics, no cookies. Its policy, set by a meta tag:

```text
default-src 'none'; script-src 'self'; style-src 'sha256-<hash of the inlined stylesheet>'; img-src 'self';
connect-src 'self'; base-uri 'none'; form-action 'none'
```

The page itself makes no requests after loading; `connect-src 'self'` is there for tools that fetch `robots.txt`
of the same site from within the page, such as Lighthouse.

The stylesheet is inlined to save a request and allowed by its SHA-256, which the generator computes on every
build; there are no style attributes and no inline scripts. GitHub Pages cannot set response headers. A host that
can should send these as well (a meta tag cannot carry `frame-ancestors`):

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'sha256-...'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

## Checks

The Pages workflow builds the page and runs Lighthouse (three runs, mobile settings) on every pull request and push
to `main`. It fails below 100 in any of performance, accessibility, best practices and SEO. The unit tests in
`tests/unit/site.bats` check that every module, group and profile is on the page, that the policy hash matches the
stylesheet and that the page has no external resources.

## Deploy

Only a push to `main` deploys, through `actions/upload-pages-artifact` and `actions/deploy-pages` with
`pages: write` and `id-token: write` for that job alone. GitHub Pages has to be enabled once in the repository
settings with the source "GitHub Actions".
