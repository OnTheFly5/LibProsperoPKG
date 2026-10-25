using System.Security.Cryptography;
using System.Text;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.Util;

namespace LibProsperoPkg.Tests;

internal static class HashTests
{
    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
    internal static void Run()
    {
        (int Length, string Hash)[] vectors =
        [
            (0, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (3, "49e580eb827c41eef7a105c0d4accdc58663ad774662ec919ee23c99214d856b"),
            (135, "3aa81a5b233ce753b2ab56b3c922338134eb11b8dc3d877d0bc8d19751684b76"),
            (136, "9f065722983c1b643b3fabbed6e791f6d74f77e6cf5a2d38c07c124465ed5d9f"),
            (137, "30efe517346c818828634cb8a3eb3538c14bc2f280132cf0261ed18a7dd85a8b"),
            (271, "5a7767ca7008df01b1c78e3a8253f409cf6d25ad5db6425309a6ce29ed7bc01b"),
            (272, "860dffd36d6a668d3cac04f1e8b99eaa980fe26172f8d34da87fc963b086e665"),
            (273, "5e0efcddf8e134669d518911b0fc762d8498516bff137166c2be548904847dda"),
            (1048576, "54ece05de46f22d2258780eb0ac856673dde47876d2cfd044885b8a8bc740020"),
        ];
        Program.Equal("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", Hex(Crypto.Sha3_256("abc"u8.ToArray())), "FIPS abc");
        foreach (var vector in vectors)
        {
            byte[] data = Enumerable.Range(0, vector.Length).Select(index => (byte)(index * 37 + 11)).ToArray();
            Program.Equal(vector.Hash, Hex(Crypto.Sha3_256(data)), "public buffer");
            using var stream = new MemoryStream(data);
            stream.Position = stream.Length;
            Program.Equal(vector.Hash, Hex(Crypto.Sha3_256(stream)), "stream rewinds");
            Program.Equal(true, stream.CanRead, "stream remains open");
            Program.Equal(vector.Hash, Hex(ProsperoPfsDigest.ComputeBlockDigest(data)), "PFS digest");
            Program.Equal(vector.Hash, Hex(ProsperoOuterPfsSignature.ComputeBlockHash(data)), "outer PFS digest");
            byte[] destination = new byte[40];
            Program.Equal(32, ProsperoPfsDigest.ComputeBlockDigest(data, destination), "destination length");
            Program.Equal(vector.Hash, Hex(destination[..32]), "destination digest");
            Program.Equal(true, destination[32..].All(value => value == 0), "destination tail unchanged");
            Program.Equal(true, ProsperoPfsDigest.VerifyBlockDigest(data, destination[..32]), "verification");
            foreach (int chunk in new[] { 1, 7, 135, 136, 137, 65536 })
            {
                using var hash = new Sha3Digest(forceManaged: true);
                for (int offset = 0; offset < data.Length; offset += chunk)
                    hash.AppendData(data.AsSpan(offset, Math.Min(chunk, data.Length - offset)));
                Program.Equal(vector.Hash, Hex(hash.GetHashAndReset()), "forced managed incremental");
                Program.Equal(vectors[0].Hash, Hex(hash.GetHashAndReset()), "incremental reset");
            }
            if (SHA3_256.IsSupported)
                Program.Equal(Hex(SHA3_256.HashData(data)), Hex(Crypto.Sha3_256(data)), "native agreement");
        }
        using (var stream = new MemoryStream("prefixabcSUFFIX"u8.ToArray()))
            Program.Equal(Hex(Crypto.Sha3_256("abc"u8.ToArray())), Hex(Crypto.Sha3_256(stream, 6, 3)), "stream range");
        Program.Throws<ArgumentException>(() => ProsperoPfsDigest.ComputeBlockDigest("abc"u8, new byte[31]));
        Program.Equal(false, ProsperoPfsDigest.VerifyBlockDigest("abc"u8, new byte[31]), "invalid expected digest size");
        Program.Equal(true, ProsperoPfsDigest.IsSupported, "portable support");
        byte[] header = Enumerable.Range(0, 24).Select(index => (byte)index).ToArray();
        Program.Equal("f34c6032e604bea43dd8fcde1369f08e6a84c82daa67649929eb15a956f7359a", Hex(ProsperoPfsDigest.ComputeFileDigest(header, "shuffle"u8, "boundary"u8, "hashes"u8)), "file digest preimage");
    }
}
