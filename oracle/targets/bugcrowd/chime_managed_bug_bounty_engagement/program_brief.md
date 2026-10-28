## ACTIVE PROGRAM — SCOPE WALL
You are hunting THIS program only.  Every finding MUST cite a source from the
in-scope assets below.  Out-of-scope assets are not a paradox — they are simply
not part of this hunt.  The rules below are axioms for this session.

**Program:** Chime Managed Bug Bounty Engagement  |  **Platform:** bugcrowd  |  **Kind:** web2
**URL:** https://bugcrowd.com/engagements/chime  |  **Max payout:** $20,000

**IN SCOPE: ⚠ SCOPE NOT LOADED**
Scope data was not available for this program at hunt time.
**MANDATORY HALT: output exactly `TARGET CLEAN` and stop.**
Do not produce any seam cards. Do not reason about any domain
found in recon data — those may belong to the platform, not the
target. A missing scope wall means no valid findings can be made.

**LOCAL ON-DISK ASSETS & CODE REPOSITORIES:**
  • .chime.com.txt (108 bytes)
  • app-qa.chime.com__login.txt (597 bytes)
  • app.chime.com.txt (261 bytes)
  • app.saltlabs.com.txt (693 bytes)
  • app.staging.saltlabs.com.txt (693 bytes)
  • apps.apple.com__us__app__chime-mobile-banking__id836215269.txt (9,330 bytes)
  • apps.apple.com__us__app__salt-work-and-get-rewarded__id1668462142.txt (4,763 bytes)
  • bugcrowd.com__.well-known__security.txt.txt (208 bytes)
  • bugcrowd.com__api_openapi.json (5,996 bytes)
  • bugcrowd.com__engagements__chime.txt (21,646 bytes)
  • bugcrowd.com__robots.txt (177 bytes)
  • bugcrowd.com__robots.txt.txt (177 bytes)
  • bugcrowd.com__security.txt (208 bytes)
  • bugcrowd.com__swagger.json (5,948 bytes)
  • chime.financial.txt (110 bytes)

**INVARIANT:** Any seam you find MUST have Assertion A sourced to this program's
documentation, policy, or UI — and Assertion B grounded in recon data or local code from the
IN SCOPE assets above.  If it cannot be grounded here, it does not exist.
Any finding citing a domain NOT listed in IN SCOPE above is automatically invalid.
The platform URL (bugcrowd.com, hackerone.com, etc.) is NEVER in scope.