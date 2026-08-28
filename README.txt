How to run
==========
Requires: .NET SDK (8 or 10), internet access for NuGet restore (first run only).

  cd poc-nostr-forgery
  # terminal 1 - malicious relay
  dotnet run --project FakeRelay

  # terminal 2 - the Wasabi update-checker replica
  dotnet run --project Poc

Expected: the Poc process prints that WasabiNostrClient ACCEPTED a forged
release announcement whose id/signature are invalid, carrying attacker URLs —
demonstrating that the client-side verification step does not exist.

Structure
=========
FakeRelay/  — a ~70-line WebSocket server speaking just enough NIP-01.
Poc/        — references the audited WalletWasabi project at commit 154c4a5
              (as ProjectReference) and uses the production WasabiNostrClient
              + CompositeNostrClient exactly as WalletWasabi.Client/Global.cs
              wires them (lines 508-523).
