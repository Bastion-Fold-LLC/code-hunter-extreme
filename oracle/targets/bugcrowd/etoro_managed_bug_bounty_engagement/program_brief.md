## ACTIVE PROGRAM — SCOPE WALL
You are hunting THIS program only.  Every finding MUST cite a source from the
in-scope assets below.  Out-of-scope assets are not a paradox — they are simply
not part of this hunt.  The rules below are axioms for this session.

**Program:** eToro Managed Bug Bounty Engagement  |  **Platform:** bugcrowd  |  **Kind:** web2
**URL:** https://bugcrowd.com/engagements/etoro-mbb-og  |  **Max payout:** $15,000

**IN SCOPE: ⚠ SCOPE NOT LOADED**
Scope data was not available for this program at hunt time.
**MANDATORY HALT: output exactly `TARGET CLEAN` and stop.**
Do not produce any seam cards. Do not reason about any domain
found in recon data — those may belong to the platform, not the
target. A missing scope wall means no valid findings can be made.

**LOCAL ON-DISK ASSETS & CODE REPOSITORIES:**
  • .etoro.com.txt (108 bytes)
  • bugcrowd.com__api_openapi.json (5,996 bytes)
  • bugcrowd.com__engagements__etoro-mbb-og.txt (13,588 bytes)
  • bugcrowd.com__robots.txt (177 bytes)
  • bugcrowd.com__security.txt (208 bytes)
  • bugcrowd.com__swagger.json (5,996 bytes)
  • com.etoro.openbook.txt (113 bytes)
  • com.etoro.wallet.txt (111 bytes)
  • delta.app.txt (257 bytes)
  • etoropartners.com.txt (4,219 bytes)
  • etorox.com.txt (5,130 bytes)
  • etorox.com__.well-known__security.txt.txt (5,338 bytes)
  • etorox.com__api-docs.txt (5,338 bytes)
  • etorox.com__openapi.json (5,338 bytes)
  • etorox.com__robots.txt.txt (5,338 bytes)

**INVARIANT:** Any seam you find MUST have Assertion A sourced to this program's
documentation, policy, or UI — and Assertion B grounded in recon data or local code from the
IN SCOPE assets above.  If it cannot be grounded here, it does not exist.
Any finding citing a domain NOT listed in IN SCOPE above is automatically invalid.
The platform URL (bugcrowd.com, hackerone.com, etc.) is NEVER in scope.