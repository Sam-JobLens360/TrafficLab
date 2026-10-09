# TrafficLab

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Language](https://img.shields.io/badge/Language-C%23-178600?logo=csharp&logoColor=white)](https://learn.microsoft.com/dotnet/csharp/)
[![Status](https://img.shields.io/badge/Status-Experimental-orange)](https://github.com/Sam-JobLens360/ParanoidCli)
[![Visibility](https://img.shields.io/badge/Repo-Public-success)](https://github.com/Sam-JobLens360/ParanoidCli)

## How to run (local LAN)

1. **Build once**:

   * `dotnet new console -n TrafficLab`
   * Replace `Program.cs` with the code above, then:
   * `dotnet add package System.CommandLine`
   * `dotnet build -c Release`

2. **Choose a 32-byte key** (hex). Example (don’t reuse):
   `6b8b4567327b23c6643c9869663348731f6bffd2c15b0a6b6a5f58c7b9f1d2a3`

3. **Start receiver** (box A):

   ```
   dotnet run -- --mode receiver --port 5000 --key 6b8b...d2a3 --outdir out
   ```

4. **Start chaff** (box B or same host):

   ```
   dotnet run -- --mode chaff --host 127.0.0.1 --port 5000 --rate 70 --jitter 0.10
   ```

5. **Send a file** (box C or same host):

   ```
   dotnet run -- --mode sender --host 127.0.0.1 --port 5000 \
     --key 6b8b...d2a3 --rate 50 --jitter 0.05 --in secret.bin
   ```

Receiver writes a concatenated plaintext file in `out/`. On the wire, **all frames are identical size** and arrive at a **steady cadence** mixed with chaff. You can crank chaff rate to study how much background noise you need before a simple traffic classifier loses confidence.

## What to poke at

* **Cadence:** vary `--rate` and `--jitter` to see what hides bursty sends.
* **Chaff ratio:** how much dummy traffic is necessary before your “active vs idle” periods are hard to spot?
* **Frame size:** change `FRAME_SIZE` to test detection sensitivity vs throughput.
* **PCAPs:** capture with Wireshark and run your own classifiers; verify there’s no content length leak and that timing is flat.

## Guardrails (so we stay clean)

* This doesn’t spoof other protocols or endpoints.
* It’s explicitly for your **own network** and **lab captures**.
* It uses standard crypto (AES-GCM) with transparent framing—no “security by obscurity.”
