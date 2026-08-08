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

Untouched graded blocks remaining, largest first: Authentication 6 (A07), Clickjacking 5,
XSSInImgTagAttribute 5 (A05), CachePoisoning 4, XSSWithHtmlTagInjection 3 (A05), plus
CryptographicFailures 1 (item 3) and JWT 1/2/3/15/16 (item 5).

Several of these classes have tests that assert the vulnerability still works. Rewriting
those to assert the fixed behaviour is the established pattern here — it kept the build at
zero failures across every batch — but it means the test file must be read before the fix
is designed, because a few tests (XXE level 2, the SSRF parameter sets) constrain *how* the
fix can be shaped.

**Method note:** batch one class per push and read the score delta before starting the next.
Per-challenge detail is withheld, so a push spanning two classes cannot be attributed.

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
