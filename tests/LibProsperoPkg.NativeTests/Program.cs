using System.Text;

int checks = 0;
void Check(byte[] actual, string expected, string context)
{
    string hex = Convert.ToHexString(actual).ToLowerInvariant();
    if (hex != expected) throw new Exception($"{context}: expected {expected}, got {hex}");
    checks++;
}

using var reusable = new LibProsperoPkg.ThirdParty.ACryptoHashNet.Sha3_256();
Check(reusable.ComputeHash(Encoding.ASCII.GetBytes("abc")), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "FIPS abc");
int cases = 0;
using var vectors = new StreamReader(typeof(Program).Assembly.GetManifestResourceStream("Sha3Vectors.tsv")
    ?? throw new InvalidOperationException("Missing embedded SHA3 vectors."));
string? line;
while ((line = vectors.ReadLine()) is not null)
{
    string[] fields = line.Split('\t');
    int length = int.Parse(fields[0]);
    string expected = fields[1];
    byte[] data = new byte[length];
    for (int index = 0; index < data.Length; index++) data[index] = (byte)(index * 37 + 11);
    Check(reusable.ComputeHash(data), expected, $"buffer {length}");
    Check(reusable.ComputeHash(data), expected, $"reuse {length}");
    using var stream = new MemoryStream(data);
    Check(reusable.ComputeHash(stream), expected, $"stream {length}");
    byte[] spanOutput = new byte[32];
    if (!reusable.TryComputeHash(data, spanOutput, out int written) || written != 32)
        throw new Exception("TryComputeHash failed");
    Check(spanOutput, expected, $"span {length}");
    foreach (int chunkSize in new[] { 1, 7, 135, 136, 137, 4096 })
    {
        using var incremental = new LibProsperoPkg.ThirdParty.ACryptoHashNet.Sha3_256();
        for (int offset = 0; offset < length; offset += chunkSize)
            incremental.TransformBlock(data, offset, Math.Min(chunkSize, length - offset), null, 0);
        incremental.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        Check(incremental.Hash!, expected, $"incremental {length}/{chunkSize}");
    }
    cases++;
}
Console.WriteLine($"PASS: {checks} SHA3-256 checks across {cases} input lengths, including FIPS abc, buffer/reuse/stream/span and six incremental chunk sizes.");
