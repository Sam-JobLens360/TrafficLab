using System;
using System.Buffers.Binary;
using System.CommandLine;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

class TrafficLab
{
    const int FRAME_SIZE = 1024;
    static readonly byte[] MAGIC = { (byte)'T', (byte)'L', (byte)'B', (byte)'1' };
    const byte VERSION = 1;
    const byte TYPE_DATA = 0;
    const byte TYPE_CHAFF = 1;

    static int Main(string[] args)
    {
        var root = new RootCommand("TrafficLab: Study traffic-analysis resistance without impersonating other services");

        var traffic = new Command("traffic", "Study traffic-analysis resistance without impersonating other services");
        Option<string> modeOpt = new("--mode") { Description = "sender | receiver | chaff", DefaultValueFactory = ParseResult => "sender" };
        Option<string> hostOpt = new("--host") { Description = "Target host (for sender/chaff)", DefaultValueFactory = ParseResult => "127.0.0.1" };
        Option<int> portOpt = new("--port") { Description = "UDP port", DefaultValueFactory = ParseResult => 5000 };
        Option<string> keyOpt = new("--key") { Description = "32-byte key in hex (required for sender/receiver)", DefaultValueFactory = ParseResult => "" };
        Option<double> rateOpt = new("--rate") { Description = "Packets per second (sender/chaff)", DefaultValueFactory = ParseResult => 50 };
        Option<double> jitterOpt = new("--jitter") { Description = "Relative jitter (0..0.5)", DefaultValueFactory = ParseResult => 0.05 };
        Option<string> infileOpt = new("--in") { Description = "Input file to send (sender)", DefaultValueFactory = ParseResult => "" };
        Option<string> outdirOpt = new("--outdir") { Description = "Receiver output dir", DefaultValueFactory = ParseResult => "." };
        Option<int> secondsOpt = new("--seconds") { Description = "Run duration; 0 = until Ctrl+C", DefaultValueFactory = ParseResult => 0 };

        traffic.Options.Add(modeOpt);
        traffic.Options.Add(hostOpt);
        traffic.Options.Add(portOpt);
        traffic.Options.Add(keyOpt);
        traffic.Options.Add(rateOpt);
        traffic.Options.Add(jitterOpt);
        traffic.Options.Add(infileOpt);
        traffic.Options.Add(outdirOpt);
        traffic.Options.Add(secondsOpt);

        traffic.SetAction(async parseResult =>
        {
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            string mode = parseResult.GetValue(modeOpt)!;
            string host = parseResult.GetValue(hostOpt)!;
            int port = parseResult.GetValue(portOpt);
            string key = parseResult.GetValue(keyOpt)!;
            double rate = parseResult.GetValue(rateOpt);
            double jitter = parseResult.GetValue(jitterOpt);
            string infile = parseResult.GetValue(infileOpt)!;
            string outdir = parseResult.GetValue(outdirOpt)!;
            int seconds = parseResult.GetValue(secondsOpt);

            if (seconds > 0) cts.CancelAfter(TimeSpan.FromSeconds(seconds));

            if (mode.ToLowerInvariant() == "sender")
            {
                if (string.IsNullOrEmpty(key) || key.Length != 64)
                {
                    Console.WriteLine("Error: --key must be a 32-byte hex string for sender mode.");
                }
                byte[] keyHex = Convert.FromHexString(key);
                await Sender(host, port, keyHex, rate, jitter, infile, cts.Token);
            }
            else if (mode.ToLowerInvariant() == "receiver")
            {
                Console.WriteLine($"mode={mode}");
                if (string.IsNullOrEmpty(key) || key.Length != 64)
                {
                    Console.WriteLine("Error: --key must be a 32-byte hex string for receiver mode.");
                }
                byte[] keyHex = Convert.FromHexString(key);
                await Receiver(port, keyHex, outdir, cts.Token);
            }
            else if (mode.ToLowerInvariant() == "chaff")
            {
                await Chaff(host, port, rate, jitter, cts.Token);
            }
            else
            {
                Console.WriteLine($"Error: Unknown mode '{mode}'. Use 'sender', 'receiver', or 'chaff'.");
            }
        });
        root.Add(traffic);

        return root.Parse(args).Invoke();
    }

    static byte[] ParseKey(string hex, bool must)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            if (must) throw new ArgumentException("--key is required for this mode.");
            return Array.Empty<byte>();
        }

        if (hex.Length != 64) throw new ArgumentException("Key must be 32 bytes (64 chars).");
        var key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return key;
    }

    public static async Task Sender(string host, int port, byte[] key, double pps, double jitter, string infile, CancellationToken ct)
    {
        if (!File.Exists(infile)) throw new FileNotFoundException("Input file not found", infile);
        byte[] data = await File.ReadAllBytesAsync(infile, ct);
        using var udp = new UdpClient();
        udp.Connect(host, port);
        ulong seq = 0;
        int offset = 0;
        var rng = RandomNumberGenerator.Create();
        var period = TimeSpan.FromSeconds(1.0 / pps);

        Console.WriteLine($"[sender] framesize={FRAME_SIZE} rate={pps:F1}pps jitter={jitter:P0} len={data.Length}");

        while (!ct.IsCancellationRequested)
        {
            bool anyLeft = offset < data.Length;
            int maxPayload = FRAME_SIZE - (4 + 1 + 8 + 8 + 12 + 16 + 2);
            int chunk = anyLeft ? Math.Min(maxPayload, data.Length - offset) : 0;

            byte[] payload = anyLeft ? data.AsSpan(offset, chunk).ToArray() : Array.Empty<byte>();
            offset += chunk;

            var frame = BuildFrame(TYPE_DATA, seq++, payload, key, rng);

            await udp.SendAsync(frame, frame.Length);
            if (!anyLeft) { /* Still sending constant-rate cover */ }

            var sleep = Jitter(period, jitter, rng);
            await Task.Delay(sleep, ct);
        }
    }

    public static async Task Chaff(string host, int port, double pps, double jitter, CancellationToken ct)
    {
        using var udp = new UdpClient();
        udp.Connect(host, port);
        ulong seq = 0;
        var rng = RandomNumberGenerator.Create();
        var period = TimeSpan.FromSeconds(1.0 / pps);
        Console.WriteLine($"[chaff] framesize={FRAME_SIZE} rate={pps:F1}pps jitter={jitter:P0}");

        while (!ct.IsCancellationRequested)
        {
            int maxPayload = FRAME_SIZE - (4 + 1 + 1 + 8 + 8 + 12 + 16 + 2);
            byte[] bogus = new byte[RandomNumberBetween(0, maxPayload, rng)];
            rng.GetBytes(bogus);
            byte[] randKey = new byte[32];
            rng.GetBytes(randKey);
            var frame = BuildFrame(TYPE_CHAFF, seq++, bogus, randKey, rng);
            await udp.SendAsync(frame, frame.Length);
            await Task.Delay(Jitter(period, jitter, rng), ct);
        }
    }

    public static async Task Receiver(int port, byte[] key, string outdir, CancellationToken ct)
    {
        Directory.CreateDirectory(outdir);
        using var udp = new UdpClient(port);
        Console.WriteLine($"[receiver] listening on port {port} -> {outdir}");
        using var outStream = File.Create(Path.Combine(outdir, $"recv_{DateTime.UtcNow:yyyyMMdd_HHmmss}.bin"));

        while (!ct.IsCancellationRequested) 
        { 
            var result = await udp.ReceiveAsync(ct);
            var frame = result.Buffer.AsSpan();
            if (frame.Length != FRAME_SIZE) continue;

            if (!frame.Slice(0, 4).SequenceEqual(MAGIC)) continue;
            byte version = frame[4];
            if (version != VERSION) continue;

            byte type = frame[5];
            ulong seq = BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(6, 8));
            long tsMs = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(14, 8));
            ReadOnlySpan<byte> nonce = frame.Slice(22, 12);
            ReadOnlySpan<byte> tag = frame.Slice(34, 16);
            ushort payLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(50, 2));
            ReadOnlySpan<byte> ctSpan = frame.Slice(52, payLen);

            try
            {
                byte[] plaintext = new byte[payLen];
                using var aes = new AesGcm(key);
                aes.Decrypt(nonce, ctSpan, tag, plaintext);
                if (type == TYPE_DATA && plaintext.Length > 0)
                {
                    await outStream.WriteAsync(plaintext, ct);
                    Console.WriteLine($"[recv] seq={seq} ts={tsMs}ms len={plaintext.Length}");
                }
            }
            catch (CryptographicException)
            {
                //Console.WriteLine($"[recv] seq={seq} ts={tsMs}ms decryption failed (likely chaff)");
            }
        }
    }

    static byte[] BuildFrame(byte type, ulong seq, byte[] payload, byte[] key, RandomNumberGenerator rng)
    {
        byte[] frame = new byte[FRAME_SIZE];
            
        MAGIC.CopyTo(frame, 0);
        frame[4] = VERSION;
        frame[5] = type;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(6, 8), seq);
        ulong ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(14, 8), ts);

        byte[] nonce = new byte[12];
        rng.GetBytes(nonce);
        Array.Copy(nonce, 0, frame, 22, 12);

        int maxPayload = FRAME_SIZE - (4+1+1+8+8 + 12+16 + 2);
        if (payload.Length > maxPayload) throw new ArgumentException($"Payload too big for frame");

        byte[] ct = new byte[payload.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(key);
        aes.Encrypt(nonce, payload, ct, tag);

        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(50, 2), (ushort)ct.Length);
        Array.Copy(tag, 0, frame, 34, 16);
        Array.Copy(ct, 0, frame, 52, ct.Length);

        return frame;
    }

    static TimeSpan Jitter(TimeSpan basePeriod, double relJitter, RandomNumberGenerator rng)
    {
        if (relJitter <= 0) return basePeriod;
        Span<byte> b = stackalloc byte[8];
        rng.GetBytes(b);
        ulong r = BinaryPrimitives.ReadUInt64BigEndian(b);
        double u = (r / (double)ulong.MaxValue) * 2 - 1;
        double factor = 1 + u * relJitter;
        if (factor < 0.1) factor = 0.1;
        return TimeSpan.FromTicks((long)(basePeriod.Ticks * factor));
    }

    static int RandomNumberBetween(int minInclusive, int maxInclusive, RandomNumberGenerator rng)
    {
        if (maxInclusive <= minInclusive) return minInclusive;
        Span<byte> b = stackalloc byte[4];
        rng.GetBytes(b);
        uint v = BinaryPrimitives.ReadUInt32BigEndian(b);
        return minInclusive + (int)(v % (uint)(maxInclusive - minInclusive + 1));
    }
}
