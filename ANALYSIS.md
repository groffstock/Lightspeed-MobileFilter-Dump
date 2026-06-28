# MobileFilter — static analysis notes

Binary is already-decrypted arm64 iOS (`cryptid=0`). Swift + ObjC NetworkExtension
content filter. App-owned Swift symbols are **stripped**; `@objc` methods are still
recoverable via ObjC metadata, pure-Swift functions are located by string xrefs.

Artifacts (regenerable with `tools/`):
- `MobileFilter.objc.h` — 77 ObjC classes, method signatures, ivars.
- `MobileFilter.swift.txt` — 392 Swift types + stored fields from `__swift5_fieldmd`.

## Tooling (`tools/`)
- `classdump.py <bin> <out.h> <binds.json>` — ObjC class-dump (resolves chained fixups).
- `swiftdump.py <bin> <out.txt>` — Swift reflection (type + stored properties).
- `disasm.py <Class> [selector] binds.json` | `disasm.py 0xADDR [n]` — annotated arm64.
- `funcsum.py binds.json 0xADDR...` — per-function string + imported-call summary.
- `funcsum.py binds.json index "<regex>"` — find functions by referenced strings.
- `binds.json` — slot-VA → external symbol map (built once via LIEF `binary.bindings`).

## Key functions (file offsets = VM − 0x100000000)

| Function        | What it does                                                            |
|-----------------|------------------------------------------------------------------------|
| `0x10001b150`   | `-[FilterDataProvider handleNewFlow:]` ObjC thunk → tail-calls Swift     |
| `0x1000165a8`   | **Swift `handleNewFlow(_:)` — the verdict engine** (see below)           |
| `0x10000c964`   | Loads API config from **Info.plist** via `NSBundle` (keys below)        |
| `0x10003250c`   | `checkLicenseApi` — decodes `LicenseCheckResponse`, stores policy        |
| `0x100027aa4`   | builds `https://sai-app-redirect.lsfilter.com/?host=` redirect           |
| `0x10005d768`   | `decodeParseJWTValues()` — decodes license JWT body                     |
| `0x10005dd54`   | extracts `bouncer_hostname` from JWT body                               |
| `0x10005e43c`   | extracts `bypass_domains` from JWT body                                 |
| `0x1000e92e0`   | Swift-JWT verify (ECDSA/RSA/HMAC via Kitura BlueECC/BlueRSA)            |

## handleNewFlow verdict model (from string literals)
Remediation/verdict categories the filter can return:
`RemediateCustomExplicit`, `RemediateBlockedCategory`, `RemediateUnknownCategory`,
`RemediateCategory`, `RemediateSealedCategory`, `RemediateCustomBlockedSearchTerm`,
`RemediateASRShutdown`, `RemediationBlockPaused` (parent pause), `RemediateLookupFailed`.
Handles both `NEFilterBrowserFlow` (URL/query/mainDocumentURL) and raw socket flows;
"EXPLICITLY DROPPING", "blocking Sealed Category", "DROPPING search for keyword".

## Config / secrets surface
`ApiRouter` (ObjC ivars) + `0x10000c964` read these from the app bundle Info.plist
(values are NOT hardcoded in this binary):
`CATEGORIZATION_DEVICE_API_URL/KEY`, `AGENT_BACKEND_API_URL`, `LICENSE_CHECK_API_KEY`,
`TELEMETRY_API_KEY`, `SIGNAL_CORE_DEVICES_API_BASE_URL`, `BASE_TRUSTED_APPS_URL`.

## Incidental
- Build-path leak: `…/mitchelllaurren-ring/…/Mobile_Filter-…/SourcePackages/checkouts/Swift-JWT/…`
- 3rd-party Swift: Starscream (WebSocket), Kitura Swift-JWT + BlueECC/BlueRSA/BlueCryptor,
  CryptorECC/CryptorRSA. Speedtest/“InsightSpeedtest” module present (`RemoteConfig` lives there).
- Telemetry payload struct fields: `agent_type, agent_version, customer_id, os, product, udid, username`.

## License / config / rules flow (traced)

App identity: **Lightspeed Systems** mobile filter — bundle `com.lightspeedsystems.iosrelayfilter`,
API namespace `sa-ios` ("smart agent iOS"). Endpoints live on the JWT-supplied
`bouncer_hostname`; `lsfilter.com` hosts the redirect/relay.

**Important correction:** filtering *rules* do NOT come from `RemoteConfig.SetConfig`.
`RemoteConfig`/`SetConfig`/"signal policy" belong to the **InsightSpeedtest / "Signal"**
subsystem (network-quality speedtests, gated by a separate speedtest license:
`0x1000c0ea4` "Skipping signal evaluation as device and speedtest license is not enabled").
The real rule source is the **UserPolicy** flow below.

1. **JWT / LSJWTSession** (`GlobalProxySettingsManager`)
   - `downloadParseDecodePacForJwt()` `0x10005bfe8` → `setJwtString` `0x100056508` (stores `_jwtString`).
   - `decodeParseJWTValues()` `0x10005d768` decodes the JWT body; signature verified with
     Swift-JWT (ECDSA/RSA/HMAC, `0x1000e92e0`).
   - Extracts from JWT body: `bouncer_hostname` `0x10005dd54` → `setBouncerHostname` `0x1000576e8`,
     and `bypass_domains` `0x10005e43c`.

2. **License check** — `checkLicenseApi` `0x10003250c` (key `LICENSE_CHECK_API_KEY` from Info.plist),
   decodes `LicenseCheckResponse`, stores policy; periodic via `startLicenseCheckTimer` `0x100027478`.
   Redirect builder `0x100027aa4` → `https://sai-app-redirect.lsfilter.com/?host=`.

3. **Policy fetch** (the actual "set config")
   - `getServerPolicy(_:)` `0x10002bb64` — retry-interval/lock gate, "Received policy for customer".
   - `getUserPolicyApi(lastPolicyAttempt:closure:)` `0x10002dad0` — POST JSON `policyRequestParams`
     to **`/filter/sa-ios/v2/user_policy`** (`0x1000081e0`/`0x10002192c`) via `NSURLSession`, JWT-authed.
   - Decode `UserPolicy` `0x10002ee00`; persist to **`userPolicy.plist`** via FILEBASEDCACHE
     `storeUserPolicy()` `0x10004fd68`; read back `currentPolicy()`/`defaultPolicy()` `0x100050040`;
     `fallbackPolicy` minimum policy `0x10004dafc`.
   - Refresh cadence: `device_policy_interval` / `last_policy_epoch_ms`; "UserPolicy expired -
     queing refetch" `0x100035978`, `asyncPolicyCallAfter` `0x100035348`.

4. **Per-host categorization** — `hostLookupApi(host:)` `0x100033880` POSTs to **`/meta/host_lookup`**,
   decodes `HostLookupResponse`, then `calling updateRules for: '…' to send it back to DataProvider`,
   stores an `NEFilterControlVerdict`.

5. **Enforcement** — `handleNewFlow` `0x1000165a8` → `verdict(url:applicationId:time:ip:currentUserEmail:)`
   / `makeVerdict(_:inASR:)` `0x10006db4c` (~49 KB) applies the policy:
   AfterSchoolRules (`pause_until` parent-pause), Sealed/blocked/allowed categories, explicit
   allow/block + wild-allow, `isDomainBypassed` (JWT `bypass_domains`), `SkipIfHostContains`/`HostContains`,
   safe-search forcing (Google `safeui=on`/setprefs, Bing `safeSearch=strict`), `blockedTerm` keyword
   regex, and proxy injection (`rocketProxyIdent`, GlobalProxy PAC). Emits a `Remediate*` verdict.

Flow: **JWT(bouncer_hostname,bypass_domains) → checkLicenseApi → getUserPolicyApi `/filter/sa-ios/v2/user_policy`
→ UserPolicy → userPolicy.plist → handleNewFlow → hostLookupApi `/meta/host_lookup` → makeVerdict → NEFilterVerdict.**

## makeVerdict precedence (`0x10006db4c`, traced branch-by-branch)

Reconstructed from string anchors + branch gating. Confirmed gating registers:
`w21 = GlobalProxyEnabled`, `w22 = isDomainBypassed`, `w19 = running verdict-action enum`
(each block ends `cmp w19,#1; b.ne …` to build the return). NB: the pervasive `tbz/tbnz w20`
tests are Swift `String` representation bits inside list-compare loops, **not** policy flags.
List membership (categories / allow / block) is the `cbz x8; cmp x10,xTARGET; b.ne` loop idiom.

Decision ladder (top = highest priority; first match short-circuits):

1. **Self/own-app special-case** — `AppBundle == com.lightspeedsystems.iosrelayfilter`,
   `xctest.online` self-fetch → "Running regular rules for … our own app".
2. **GlobalProxy gate** (`w21`) — if enabled: check proxy available / "global proxy not
   reachable". On the proxy-available path, `isDomainBypassed` is consulted *early*
   (`0x705a0 cbz x0 → bypass block`), i.e. bypass can short-circuit before category eval.
3. **Sealed Category / explicit block** — category-membership loop (`0x71454`) →
   "Sealed Category … explicitly blocked" ⇒ **BLOCK** (high-priority deny).
4. **AfterSchoolRules — pause_until (early)** — if `pause_until` active (time check
   `cmp x21,x8`) ⇒ "AfterSchoolRules FILTERED because pause_until" ⇒ **BLOCK** everything.
   ("pause_until NOT FOUND in policy" falls through.)
5. **isDomainBypassed** (`w22`) — domain ∈ JWT `bypass_domains` ⇒ "isDomainBypassed true for:"
   ⇒ **ALLOW** (bypass).
6. **pacURL** check → **SkipIfHostContains / HostContains** substring host rules.
7. **Explicitly wild allowed** (wildcard allow list) ⇒ **ALLOW**.
8. **rocketProxyIdent** (proxy injection) — "matches host with no /login" → append ident
   "allow it through" (**ALLOW**), or "requires remediation update" → append `rocketIdent`.
9. **Explicitly allowed** (exact allow list) ⇒ **ALLOW**.
10. **blockedTerm keyword regex** + **safe-search forcing** — Bing `safeSearch=strict`,
    Google `safeui=on`/setprefs/filter-thumbnails (rewrites the URL/query, not a block).
11. **Explicitly blocked** (second exact block-list pass) ⇒ **BLOCK**.
12. **AfterSchoolRules default resolution** — "pause_until is DISABLED" → either
    "UNFILTERED In Effect. Allowing Traffic" (**ALLOW**) or "OFF In Effect. Blocking Traffic"
    (**BLOCK**) — the fall-through default when no explicit rule matched.
13. **Finalize** — append query params (`rocketProxyIdent`/`rocketIdent`), log "Make verdict
    with Query Parameters added", return the `Remediate*` verdict to `handleNewFlow`.

Net precedence: **own-app → sealed/explicit-block → ASR pause(block) → bypass(allow) →
host-substring/wild-allow → rocket-proxy(allow) → explicit-allow → safe-search rewrite →
explicit-block → ASR default(allow/block)**. Block rules (sealed category, ASR pause) and the
bypass allow sit above the generic allow/block lists; the ASR mode is the final tie-breaker.
(Ordering of steps 3–5 is mode-dependent: on the GlobalProxy-available path, bypass is tested
before the category loop. Exact tie-breaks beyond this would need decompiler dataflow.)

Raw ordered trace: `scratchpad/makeverdict.trace`; regenerate with `tools/trace.py binds.json 0x10006db4c`.

## getUserPolicyApi request body (`policyRequestParams`)

`POST https://<bouncer_hostname>/filter/sa-ios/v2/user_policy`, `Content-Type: application/json`,
JWT-authed, encoded from Swift struct `PolicyRequestParams` (`0x10002dad0`).

Wire keys are **camelCase** (synthesized `CodingKeys`, default raw values; no
`convertToSnakeCase` strategy exists in the binary — verified). The camelCase key strings sit
contiguous in `__cstring` in field order (`udid,platform,agentVersion,lastPolicyEpochMS`).
The snake_case look-alikes (`user_email`,`agent_version`,`last_policy_epoch_ms`) belong to the
**JWT-claims** model instead (clustered with `exp`/`iat`/`nbf`/`customer_id`/`user_guid`).

| JSON key            | Swift type | meaning                                                    |
|---------------------|------------|------------------------------------------------------------|
| `userEmail`         | String     | current user's email (from JWT `local_user_email`)         |
| `udid`              | String     | device id                                                  |
| `platform`          | String     | OS platform ("iOS")                                        |
| `agentVersion`      | String     | agent/app version (Info.plist)                            |
| `lastPolicyEpochMS` | Int        | epoch-ms of last fetched policy (delta/refresh gating)     |

Example body:
```json
{"userEmail":"…","udid":"…","platform":"iOS","agentVersion":"…","lastPolicyEpochMS":0}
```
Encode-failure path logs "Cannot encode policyRequestParams: …"; a guard rejects fetching a
policy for a different user ("Not allowed to fetch policy for another …").

## UserPolicy response schema (`/filter/sa-ios/v2/user_policy`)

Decoded by `0x10002ee00` ("UserPolicy could not be decoded"), cached to `userPolicy.plist`.
Root type's Swift name is an indirect symbolic ref (shows as `T` in reflection); fields +
nested models below (wire keys = field names — mixed camel/snake, taken verbatim from server
JSON; `pause_until`, `signal_*`, `ios_trusted_apps_timestamp` are the only snake_case ones).
Type shorthands: `SaySSG`=`[String]`, `SaySiG`=`[Int]`, `SayTG`=`[<struct>]`, `T`=`Date`/nested.

```
UserPolicy {
  contentFilter: ContentFilter        // primary filtering rules
  videos: Videos                      // YouTube/video controls
  version: String
  canOverride: Bool                   // user may override a block
  flaggedTerms: [String]?
  flagSettings: {…}?
  asr: ASR                            // After-School-Rules schedule
  asrPolicy: ASRPolicy                // After-School-Rules ruleset + pause
  fetchedDate: Date
  userIp: String
  generatedAt: Int
  lsCategories: [LSCategory]          // category id -> name map
  rocketIdent: String                 // proxy-injection ident
  rocketProxyIdent: String            // proxy-injection ident (proxy mode)
  coEntKey: String?                   // "ek" / co-ent key (overridable)
  licensing: Licensing?
  ios_trusted_apps_timestamp: Int?
  // _fileBasedCache: local-only cache wrapper (not on the wire)
}

ContentFilter {                       // (rich variant used by UserPolicy)
  categories: Categories
  googleForceSafesearch: Bool?        // -> "Google: Forcing safe search"
  bypassOnFailure: Bool               // fail-open vs fail-closed when proxy unreachable
  chromebookOnly: Bool
  googleFilterDomainsList: String?
  googleFilterThumbnails: Bool?        // -> "Google: Filter thumbnails"
  lists: Lists
}
Categories { blocked:[Int]  overrides:[Int]  lockouts:[Int]  readOnly:[Int] }  // category IDs
Lists      { allowed:[…]?  blocked:[…]?  keywords:[…]? }   // -> explicit allow/block + blockedTerm
LSCategory { id:Int  categoryId:Int  name:String  shortDesc:String }

ASR        { mode: Mode{ state:String  weekdayBlock:TimeBlock  weekendBlock:TimeBlock }  ipRanges:[String]? }
TimeBlock  { start:String  end:String }                    // ASR active window
ASRPolicy  { contentFilter: ContentFilter  videos: Videos  pause_until: Int? }   // pause_until -> parent-pause

Videos     { mode/blocked/videoMode, smartPlay: SmartPlay{ allowedCategoryIds:[Int]?  blockedCategoryIds:[Int]?  blockOtherVideos:Bool }, youtubeHideThumbnails, youtubeHideComments }

Licensing  { interval:Double  timeStamp:Date  digitalInsight:Service  filter:Service
             signal_app:Service  signal_device:Service  signal_internet:Service }
Service    { status: LicenseStatus  expiration: Date }     // per-feature license gating
```

Enforcement linkage (→ `makeVerdict` ladder above):
- `contentFilter.categories.{blocked,lockouts}` + `lsCategories` → "Sealed Category / explicitly blocked".
- `contentFilter.categories.overrides` + `canOverride` → user-override allow.
- `contentFilter.lists.{allowed,blocked,keywords}` → explicit allow / explicit block / `blockedTerm` regex.
- `contentFilter.googleForceSafesearch` / `googleFilterThumbnails` → safe-search rewrite.
- `contentFilter.bypassOnFailure` → behavior when "global proxy not reachable".
- `asrPolicy.pause_until` → "AfterSchoolRules FILTERED because pause_until"; `asr.mode` + TimeBlocks → ASR ON/OFF/UNFILTERED schedule.
- `rocketIdent` / `rocketProxyIdent` → query-param proxy injection.
- `licensing.*.status` → feature gates (e.g. "no license in policy", speedtest/signal gating).

## Videos / SmartPlay (YouTube controls)

```
Videos {                              // UserPolicy.videos
  youtubeHideThumbnails: Bool?        // hide YT thumbnails
  youtubeHideComments: Bool?          // hide YT comments
  mode: Mode { blocked: Bool  videoMode: String? }   // video block + mode ("strict"/"moderate"/…)
  smartPlay: SmartPlay {
    allowedCategoryIds: [Int]?        // YT category IDs allowed
    blockedCategoryIds: [Int]?        // YT category IDs blocked
    blockOtherVideos: Bool            // block anything not in allowed set
  }
}
```
Enforcement: a video flow → `blocked`/`videoMode` gate, then SmartPlay category-ID membership
(`allowed`/`blocked`CategoryIds) with `blockOtherVideos` as the default; thumbnails/comments
stripped via query/headers. Maps to verdict reasons `categoryVideoBlocked`,
`customCategoryVideoBlocked`, `blockedUnclassifiedVideo`, `allowedExplicitlyVideo`.
(ASRPolicy carries a separate slim `Videos { mode: Mode }` for after-school hours.)

## Category taxonomy — IDs are opaque Ints; names are server-delivered

There is **no hardcoded category name table in the binary.** `category_t` resolves to
`Si8category_t` = **`typealias category_t = Int`**; the engine only does integer set-membership
against the policy's ID lists. Human-readable names arrive at runtime inside the policy:

```
LSCategory { id: Int  categoryId: Int  name: String  shortDesc: String }   // UserPolicy.lsCategories[]
```
ID lists that drive decisions: `contentFilter.categories.{blocked,overrides,lockouts,readOnly}: [Int]`
and `videos.smartPlay.{allowed,blocked}CategoryIds: [Int]`. The `cat: Int` from `/meta/host_lookup`
is matched against these. So to "map IDs → names" you must capture a live `lsCategories` array
(or query the server's taxonomy endpoint) — it cannot be extracted statically.

Related verdict typealiases: `match_t/term_t/param_t/type_t` are all `String` (`SS…`);
`category_t` is `Int`.

## /meta/host_lookup — HostLookupResponse

`POST https://<bouncer_hostname>/meta/host_lookup` (`hostLookupApi(host:)` `0x100033880`),
`Content-Type: application/json`, body `{"host":"<host>"}` (`LookupRequest`). Response:

```
HostLookupResponse {
  data: DataModel {
    response: LookupResponse {
      request: LookupRequest { host: String }
      cat: Int          // resolved category ID (-> matched against UserPolicy ID lists)
      action: String    // server-suggested action verdict
    }
  }
}
```
i.e. wire JSON `{"data":{"response":{"request":{"host":"…"},"cat":<int>,"action":"…"}}}`.
On success → `updateRules` → stores an `NEFilterControlVerdict`; failures log
"hostlookupapi error/server error", "HostLookupResponse could not be decoded", and yield the
`blockedLookupFailed` / `RemediateLookupFailed` verdict. Repeated failures tracked via
`hostFailedCategorizationCount`.

## VerdictReason — full outcome taxonomy

The authoritative enum behind the `makeVerdict` log strings (`category_t`=Int, others=String):
`allowed`, `allowedWithCategory(Int)`, `allowedButRequiresQueryParameter(String)`,
`allowedInternalWhitelist(String)`, `allowedExplicitly{Host,Wild,Video}(String)`,
`allowedASRUnfiltered`, `allowedLicenseLapsed`, `allowedConversationFragment`, `allowedJwtString`,
`mustAskServer`, `categoryHostBlocked(Int)`, `customCategoryHostBlocked(Int)`,
`categoryVideoBlocked(Int)`, `customCategoryVideoBlocked(Int)`, `blockedExplicitly{Host,Wild,Video}(String)`,
`blockedUnclassifiedVideo`, `searchTermBlocked(String)`, `categorySealedBlocked(Int)`,
`blockedASRShutdown`, `blockedLookupFailed`, `blockedParentPause`, `requiresRemediationUpdate`.
("ek"/`coEntKey` drives the `digitalEquityCheck()` path — "skipping digitalEquity because ek is not in policy".)

## Next (in Ghidra/IDA)
Load at base `0x100000000`, import these addresses as the entry points above. The pure-Swift
verdict logic in `0x1000165a8` is large (~17 KB) and value-witness heavy — decompile there,
not via linear capstone.
