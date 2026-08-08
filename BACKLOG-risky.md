# VulnerableApp — risky items for discussion

Items deliberately NOT fixed, or fixed in a way worth a second look. Raised rather than
guessed at, per "if it seems extra risky, back-log it".

## Score history

70/187 (32/110) → **94/187 (52/110)** at `3345e97`, from parameterizing SQLi, validating the
command-injection host, disabling XXE entities, escaping LDAP filters, taking IDOR identity
from the token/DB, and restricting SSRF to external http(s).

Untouched graded blocks remaining, largest first: Http3xx 9 (item 1), PersistentXSS 6
(item 7), Authentication 6, Clickjacking 5, XSSInImgTagAttribute 5, CachePoisoning 4,
XSSWithHtmlTagInjection 3, plus CryptographicFailures 1 (item 3) and JWT 1/2/3/15/16 (item 5).

Several of these classes have tests that assert the vulnerability still works. Rewriting
those to assert the fixed behaviour is the established pattern here — it kept the build at
zero failures across both batches — but it means the test file must be read before the fix
is designed, because a few tests (XXE level 2, the SSRF parameter sets) constrain *how* the
fix can be shaped.

## 1. Http3xxStatusCodeBasedInjection (9 graded levels) — needs a better rule

`WHITELISTED_URLS` contains only `"/"` and `"/VulnerableApp/"`, but the levels legitimately
redirect to bare relative values such as `somedomain.com`. Enforcing that set in the shared
`getURLRedirectionResponseEntity` broke **four tests asserting legitimate same-origin
redirects** (levels 2, 3, 4, 5) — genuine regressions, not vulnerability assertions.

The correct rule is probably *"reject absolute or scheme-relative URLs whose host differs from
the request host"* rather than an exact-match set. Needs care around `//evil.com`, `\/\/evil.com`,
`%09`/`%00` tricks and case. Attempted and reverted; not currently in the branch.

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

## 7. PersistentXSSInHTMLTag (6 levels) — chokepoint escaping double-escapes

`getCommentsPayload` is the shared chokepoint and takes a per-level
`Function<String,String>` transform; Level 1 passes `post -> post`, i.e. raw injection into a
`<div>`. Escaping the content at the chokepoint is the right shape, but some levels (at least
6, and the pattern-replacement paths in 2 and 3) already transform or escape, so a blanket
`escapeHtml4` there double-escapes and broke three tests asserting exact output.

The fix likely needs to escape only on the levels that currently pass content through
unmodified, or to replace each level's transform rather than wrap it. Attempted and reverted;
not in the branch.

The same file also had `nullByteVulnerablePatternChecker`, which truncated at a null byte before
pattern matching. **Fixed in `a5ee814` — scored zero** (70/187 before and after).

That result sharpens the diagnosis above: the null byte was never the only way past levels 4 and
5. Their blocklist is `(<img)|(<input)+`, so `<image src=x onerror=alert(1)>` passes through
untouched — `<image` does not contain the substring `<img`. Levels 4/5 cannot score while the
blocklist stands, no matter what the checker does, so they depend on the escaping fix in this
item rather than being independent of it. The commit is kept because it closes a genuine bypass
and cost nothing, not because it moved the rubric.
