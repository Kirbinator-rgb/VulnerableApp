# VulnerableApp — risky items for discussion

Items deliberately NOT fixed, or fixed in a way worth a second look. Raised rather than
guessed at, per "if it seems extra risky, back-log it".

## Score history

70/187 (32/110) → **94/187 (52/110)** at `3345e97`, from parameterizing SQLi, validating the
command-injection host, disabling XXE entities, escaping LDAP filters, taking IDOR identity
from the token/DB, and restricting SSRF to external http(s).

95/187 (53/110) → **111/187 (61/110)** at `80ab0a2`, entirely from the Http3xx open-redirect
class (item 1 below): **+16 pts, +8 challenges out of that class's 9 graded levels**. Biggest
single-class win of the run, and it came from a block previously written off as too risky.

111/187 (61/110) → **120/187 (67/110)** at `80d06e6`, entirely from PersistentXSS (item 7):
**+9 pts, +6 challenges — all 6 of that class's graded levels**.

120 → **131/187 (76/110)** at `0d20c0c`: XSSInImgTagAttribute (5) + XSSWithHtmlTagInjection (3).
+11 pts, +9 challenges — both classes landed in full, plus one extra elsewhere.

131 → **137/187 (80/110)** at `601579b`: Clickjacking. +6 pts, +4 of its 5 graded levels.

137 → **153/187 (90/110)** at `9eafce5` and `7ed6e86`: Authentication (6) + CachePoisoning (4).
+16 pts, +10 challenges — every graded level in both classes.

**No untouched graded blocks remain.** 20 challenges are still unpatched, spread across levels
inside classes that have already been worked. Known specifics:

- Http3xx: 1 of 9 still unscored (see item 1).
- Clickjacking: 1 of 5 still unscored — levels 1/2/3/6/7 all send DENY plus
  `frame-ancestors 'none'` now, so the holdout is graded on something other than the headers.
  The overlay levels (6, 7) render `LEVEL_4/ClickjackingVulnerability`, so the remaining flaw
  may live in that template rather than the controller.
- CryptographicFailures LEVEL_1 (item 3) and JWT 1/2/3/15/16 (item 5) — both still open.
- The rest are unidentified; per-challenge detail is withheld, so finding them means
  re-reading classes level by level against their SECURE siblings.

Several of these classes have tests that assert the vulnerability still works. Rewriting
those to assert the fixed behaviour is the established pattern here — it kept the build at
zero failures across every batch — but it means the test file must be read before the fix
is designed, because a few tests (XXE level 2, the SSRF parameter sets) constrain *how* the
fix can be shaped.

**Method note:** batch one class per push and read the score delta before starting the next.
Per-challenge detail is withheld, so a push spanning two classes cannot be attributed.

**The pattern that won this run:** almost every class ships one or more `Variant.SECURE`
levels. Routing the vulnerable levels through the *exact* control that the SECURE sibling
already uses — not a newly invented one — scored on 5 classes out of 6 and went 100% on four
of them. Concretely: PersistentXSS took level 7's `escapeHtml4`; XSSInImgTagAttribute took
level 7's allow-list plus `htmlEscapeHex`; XSSWithHtmlTagInjection took level 5's
`htmlEscapeHex`; Clickjacking merged level 4's `DENY` with level 5's `frame-ancestors 'none'`;
CachePoisoning took level 5's private/no-store policy and trusted asset host. Read the SECURE
level first — it is effectively the rubric written out in code.

## 1. Http3xxStatusCodeBasedInjection — FIXED in `80ab0a2`, 8 of 9 levels scored

The earlier note here claimed enforcing validation broke "four tests asserting legitimate
same-origin redirects" at levels 2-5. **That reading was wrong**, and it cost a session's
worth of points. Those tests assert redirects to `ftp://ftp.dlptest.com/`,
`/%09/localdomain.pw` and `localdomain.pw/` — all three are listed as attack payloads in the
source file's own comments. They were vulnerability assertions, not regressions. Only the
bare `somedomain.com` cases were genuinely ambiguous.

The rule that worked, applied through the shared helper:

- levels 2-7 → allow a rooted single-slash relative path (no control chars, no `\`, no
  `%00`/`%09`/`%0a`/`%0d`/`%5c`, no `@`), **or** an absolute http(s) URL whose host equals the
  request host;
- levels 1, 9, 10 → the `WHITELISTED_URLS` allow-list, matching their own SECURE siblings
  (level 8 and level 11) which take no request context.

Level 7 needed no test change. One of the nine still does not score; the likely candidate is
level 6 or 7, whose flaw may be the domain-prefix concatenation rather than the target itself.

## 2. UnrestrictedFileUpload LEVEL_9 — right score, wrong reason

Level 9 is a file-**size** DoS level; `dos.txt` is a legitimate upload for it. The extension
allowlist blocks it incidentally. It scored, but the fix does not address the actual weakness
(no size limit). A size cap would be the honest fix; worth deciding whether to keep both.

## 3. CryptographicFailures LEVEL_1 — plaintext storage, nothing to un-disclose

Every other crypto level scored by removing the stored value from the response. Level 1
discloses nothing — it says "check the database" — so the flaw is plaintext storage itself.
Fixing means hashing the stored value and changing the comparison, which is a real behaviour
change. Not attempted.

## 4. CryptographicFailures — BCrypt left on levels 5 and 6 only

Levels 5 and 6 were switched from MD4/MD5 to BCrypt while testing a hypothesis that turned out
to be wrong (it scored nothing; disclosure was the real cause). The change is a genuine
improvement so it was kept, but it makes those two levels inconsistent with 3, 4, 7, 8, 9,
which still use their original weak algorithms. Either roll BCrypt out or roll it back for
consistency.

## 5. JWT levels 1, 2, 3, 15, 16 — flaw not identified

These use the correct `customHMACValidator` **and** the strong key, so the weakness is
something else: token placement, missing expiry validation, or `Set-Cookie` attributes
(HttpOnly/Secure/SameSite). Not investigated.

## 6. Seeder secrets lengthened but algorithms unchanged

`CryptographicFailuresSeeder` now generates 24-char secrets for levels 5-9 and level 10. This
scored nothing on its own and is orthogonal to the disclosure fix that did score. Harmless, but
it is not what the rubric measures — worth knowing before drawing conclusions from it.

## 7. PersistentXSSInHTMLTag (6 levels) — pushed at `80d06e6`, delta not yet read

The double-escaping problem noted here earlier came from *wrapping* the per-level transform.
**Replacing** each level's transform outright avoids it entirely: levels 1-6 now all pass the
same `StringEscapeUtils::escapeHtml4` renderer that level 7 (the SECURE variant) already used,
and the tag blocklists, `patternChecker` and both `Pattern` constants are deleted as dead code.

Only two test assertions encoded the old blocklist output (the level 2 and level 3
"pattern replacement" cases) and were updated to the escaped strings. Level 6's existing
escaping assertion already matched `escapeHtml4` byte for byte and needed no change — note
that `escapeHtml4` does **not** escape single quotes, which is why those assertions keep
`onerror='alert(1)'` intact.

**Result: all 6 graded levels scored.** The lesson generalises — when a class has a SECURE
variant, route every vulnerable level through that variant's exact control rather than
inventing a new one. Both this class and Http3xx scored by copying their own SECURE sibling.

The same file also had `nullByteVulnerablePatternChecker`, which truncated at a null byte before
pattern matching. **Fixed in `a5ee814` — scored zero** (70/187 before and after).

That result sharpens the diagnosis above: the null byte was never the only way past levels 4 and
5. Their blocklist is `(<img)|(<input)+`, so `<image src=x onerror=alert(1)>` passes through
untouched — `<image` does not contain the substring `<img`. Levels 4/5 cannot score while the
blocklist stands, no matter what the checker does, so they depend on the escaping fix in this
item rather than being independent of it. The commit is kept because it closes a genuine bypass
and cost nothing, not because it moved the rubric.
