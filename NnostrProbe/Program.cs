using System.Net.WebSockets;
using NNostr.Client;
using NNostr.Client.Protocols;

class Probe
{
    static async Task Main()
    {
        var relayUri = new Uri("ws://127.0.0.1:7777");
        void NoTor(WebSocket ws) { }
        var client = new NostrClient(relayUri, NoTor);

        client.MessageReceived += (s, m) => Console.WriteLine($"[PROBE] MessageReceived event fired");
        client.InvalidMessageReceived += (s, m) => Console.WriteLine($"[PROBE] INVALID MESSAGE EVENT: {m}");
        client.EventsReceived += (s, e) => Console.WriteLine($"[PROBE] EVENTS RECEIVED: sub={e.subscriptionId} count={e.events.Length}");
        client.EoseReceived += (s, m) => Console.WriteLine($"[PROBE] EOSE {m}");
        client.NoticeReceived += (s, m) => Console.WriteLine($"[PROBE] NOTICE {m}");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await client.ConnectAndWaitUntilConnected(cts.Token);
        Console.WriteLine("[PROBE] connected");
        await client.CreateSubscription("probe-sub-1", new[]{ new NostrSubscriptionFilter { Kinds = new[]{1}, Limit = 1 } }, cts.Token);
        Console.WriteLine("[PROBE] subscribed, waiting for relay event...");
        await Task.Delay(TimeSpan.FromSeconds(15));
    }
}
