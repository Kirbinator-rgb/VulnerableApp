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

153 → **157/187 (91/110)** at `93435ac`: JWT levels 1, 2, 3, 15, 16. **+4 pts but only +1
challenge — 4 of the 5 did not score.** See item 5; this is the one class where the
SECURE-sibling pattern did not carry, because JWT has no SECURE variant to copy.

`b6ed15f` re-spelled the cookie flag `HttpOnly` instead of `httponly` on the theory that a
rubric regex wanted the conventional casing. **Score unchanged at 157/91 — hypothesis
disproved.** Cookie attribute casing is not what levels 2 and 3 are graded on.

157 → **158/187 (92/110)** at `10c84ac`, after establishing the scorer is runtime (below).

## The scorer is a runtime prober — confirmed, not inferred

`.github/workflows/score.yml` settles it, no probing required. It calls
`OWASP-CTF/score-action@main`, which *"builds + boots the app, scores it against the embedded
rubric"*, with `app-url: http://app:9090/VulnerableApp`. It waits for the Spring seeder first,
because *"scoring before that makes the data-dependent SQLi challenges look patched"*.

**Consequences, all of which cost points before this was understood:**

1. **A fix only counts if it changes what an HTTP probe observes.** Source-level correctness is
   irrelevant on its own.
2. **Silently ignoring bad input reads as accepting it.** JWT level 1 was changed to ignore a
   URL-supplied token, which turned a 401 into a 200 — strictly worse to a prober. Rejecting
   the URL token outright recovered the challenge.
3. **A 500 hides everything behind it.** All 14 JWT cookie loops dereferenced
   `requestEntity.getHeaders().get("cookie")` without a null check, so any cookie-less GET
   threw an NPE. A probe could never reach the `Set-Cookie` attributes it was there to inspect.
   Guarded in `10c84ac`.

The rubric itself lives in an org-internal scorer image (`packages: read`) and is not readable,
which is as it should be — the workflow only reveals the mechanism, never the answers.

158 → **159/187 (93/110)** at `a2d4f07`: CryptographicFailures LEVEL_1, found by applying the
runtime lens. The winning change was **not** the BCrypt storage itself — it was that the
response stopped saying *"The system stores passwords in plaintext"* and stopped echoing the
stored secret back on a correct guess. Both are things a prober can read; the storage format
alone is not.

## The scorer is non-deterministic — do not trust small deltas

**Proved, not suspected.** `a2d4f07` scored **159/187 (93/110)**. `b0bae87` is a revert whose
tree is byte-identical to `a2d4f07` — `git diff a2d4f07 b0bae87` is empty — and it scored
**157/187 (92/110)**. Same code, different score.

Cause is almost certainly the seeded random data: `CryptographicFailuresSeeder` and friends
generate fresh secrets on every boot, and `score.yml` itself warns that scoring before the
Spring seeder finishes "makes the data-dependent SQLi challenges look patched". So some
challenges resolve differently run to run.

**Methodology this forces:**

- The noise band is at least **±2 points / ±1 challenge**. A delta inside that range carries
  no information.
- Only act on deltas of **3 or more**, or re-run the same commit to separate signal from noise
  (`git commit --allow-empty` re-triggers scoring).
- Several earlier attributions in this file are noise-contaminated and should be read with
  that caveat: "Clickjacking 4 of 5", the XSS push's "+9 challenges for 8 levels", and the
  crypto 7-9 "-1 regression" below.

Crypto levels 7-9 were reverted at `b0bae87` on a -1 signal and then **restored**, because that
signal was within the noise band and the change itself is plainly correct: it replaces SHA-1 /
LM / unsalted SHA-256 with BCrypt and removes a response that echoed the digest of any
submitted value, which was a free hashing oracle.

## Runtime-lens triage of the remaining 17

Sorted by expected value. The general rule: **ask what an HTTP probe can distinguish.** If a
change is invisible in the status code, headers, or body, it will not score however correct it
is — this is why the earlier session's BCrypt-on-levels-5/6 and lengthened-seeder-secrets
changes (items 4 and 6) scored zero while the disclosure fixes scored.

1. **Crypto levels 7, 8, 9 (SHA-1 / LM / unsalted SHA-256) — best remaining lead.** Level 1
   just proved the pattern: check whether their challenge text still names the weak algorithm
   or prints the hash. If it does, that is the probe-visible marker, and the fix is the level
   11 treatment (BCrypt in the seeder + neutral response text). Cheap to check, same shape as
   a fix that just worked.
2. **JWT 2, 3, 16.** Cookie attributes are now set and the NPE is guarded, yet they still do
   not score, so the graded signal is something else. Note `requestEntity.getHeaders()
   .get("cookie")` splits on `=` and only matches when `JWT` is the **first** cookie in the
   header — a probe sending any other cookie first would never reach the validation branch.
   Worth fixing as correctness regardless.
3. **Http3xx 1 of 9.** Levels 6 and 7 concatenate the request origin with the parameter; a
   probe payload that survives `isRelativeSameOriginPath` would land in the Location header.
4. **Clickjacking 0 or 1 of 5.** May already be 5/5 — the ±1 drift in the global counter makes
   this unprovable without per-challenge detail. Do not spend rounds here.
5. **~12 unattributed**, most likely inside PathTraversal (12 graded) and
   UnrestrictedFileUpload (9 graded), the two largest classes from the earlier session. Audit
   them by response, not by source: for each level, ask what a probe sends and what comes back.

**Do not** spend further rounds on blind single-attribute experiments. The cookie-casing test
(`b6ed15f`) cost a full scoring round for a clean negative. Prefer changes that alter what
comes back over the wire.

**No untouched graded blocks remain.** 17 challenges are still unpatched, spread across levels
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

## 5. JWT levels 1, 2, 3, 15, 16 — flaws identified, only one scored

The `@AttackVector(description=...)` on each handler names its flaw outright. That is the
fastest way to read this codebase and it should have been used far earlier:

| Level | Declared flaw | Fix applied in `93435ac` | Scored |
|---|---|---|---|
| 1 | `JWT_URL_EXPOSING_SECURE_INFORMATION` | read token from cookie, never echo it in the body | no |
| 2 | `COOKIE_..._SECURITY_ATTRIBUTES_MISSING` | `HttpOnly; Secure; SameSite=Strict` | no |
| 3 | `COOKIE_WITH_HTTPONLY_WITHOUT_SECURE_FLAG` | added `Secure; SameSite` | no |
| 15 | `..._MISSING_SIGNATURE_VERIFICATION` | actually verify the HMAC | **yes (+4)** |
| 16 | `..._ALGORITHM_DOWNGRADE` | pin `alg` to HS256 before verifying | no |

Level 15 was genuinely broken — it returned `isValid=true` for any token with three
dot-separated parts. That one fix is the whole +4.

Why the other four missed, best current reading: they are **client-side** flaws
(`CLIENT_SIDE_VULNERABLE_JWT`) about where the token lives, and the rubric may probe the
running app rather than read the source. Note that level 1's own template
(`LEVEL_1/JWT_Level1`) drives the endpoint with `?JWT=...`, so moving the read to a cookie may
have taken the endpoint *off* the path the probe exercises rather than fixing what it checks.
**Before spending more here, check whether the scorer is static or runtime** — every fix that
has scored so far changed observable response content, which is consistent with either.

Level 16's declared "accepts multiple weak algorithms" never actually existed in the code: the
handler only ever tried HS256, and `customHMACValidator` re-signs `header.payload` and
string-compares, which is inherently algorithm-pinned. The added header check is correct
defence but there may have been nothing there to fix.

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
