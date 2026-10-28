## ACTIVE PROGRAM — SCOPE WALL
You are hunting THIS program only.  Every finding MUST cite a source from the
in-scope assets below.  Out-of-scope assets are not a paradox — they are simply
not part of this hunt.  The rules below are axioms for this session.

**Program:** Zendesk Managed Bug Bounty Engagement  |  **Platform:** bugcrowd  |  **Kind:** web2
**URL:** https://bugcrowd.com/engagements/zendesk  |  **Max payout:** $50,000

**IN SCOPE:**
  • https://*.zendesk.com [URL]
  • https://*.zendesk.com [URL]
  • https://*.zendesk.com [URL]
  • https://*.zendesk.com [URL]
  • https://github.com/zendesk [OTHER]
  • https://github.com/Tymeshift [OTHER]
  • https://github.com/klausapp [OTHER]
  • https://github.com/ultimateai [OTHER]
  • https://github.com/zendesk https://github.com/Tymeshift https://github.com/klausapp https://github.com/ultimateai [OTHER]
  • https://*.zendesk.com [URL]

**OUT OF SCOPE (never probe these):**
  • support.zendesk.com
  • www.zendesk.com

**LOCAL ON-DISK ASSETS & CODE REPOSITORIES:**
  • .zendesk.com.txt (110 bytes)
  • bugcrowd.com__.well-known__security.txt.txt (208 bytes)
  • bugcrowd.com__api-docs.txt (293 bytes)
  • bugcrowd.com__api_openapi.json (5,996 bytes)
  • bugcrowd.com__engagements__zendesk.txt (17,393 bytes)
  • bugcrowd.com__robots.txt (177 bytes)
  • bugcrowd.com__robots.txt.txt (177 bytes)
  • bugcrowd.com__security.txt (208 bytes)
  • bugcrowd.com__swagger.json (5,996 bytes)
  • program_page.txt (107,753 bytes)
  • screenshot.png (54,938 bytes)
  • [CLONED REPO] zcli/ (full source code on-disk at targets/bugcrowd/zendesk_managed_bug_bounty_engagement/zcli)
  • [CLONED REPO] zendesk_api_client_php/ (full source code on-disk at targets/bugcrowd/zendesk_managed_bug_bounty_engagement/zendesk_api_client_php)
  • [CLONED REPO] copenhagen_theme/ (full source code on-disk at targets/bugcrowd/zendesk_managed_bug_bounty_engagement/copenhagen_theme)
  • [CLONED REPO] credit_card_sanitizer/ (full source code on-disk at targets/bugcrowd/zendesk_managed_bug_bounty_engagement/credit_card_sanitizer)
  • [CLONED REPO] radar/ (full source code on-disk at targets/bugcrowd/zendesk_managed_bug_bounty_engagement/radar)
  • [CLONED REPO] zendesk_api_client_rb/ (full source code on-disk at targets/bugcrowd/zendesk_managed_bug_bounty_engagement/zendesk_api_client_rb)

**INVARIANT:** Any seam you find MUST have Assertion A sourced to this program's
documentation, policy, or UI — and Assertion B grounded in recon data or local code from the
IN SCOPE assets above.  If it cannot be grounded here, it does not exist.
Any finding citing a domain NOT listed in IN SCOPE above is automatically invalid.
The platform URL (bugcrowd.com, hackerone.com, etc.) is NEVER in scope.