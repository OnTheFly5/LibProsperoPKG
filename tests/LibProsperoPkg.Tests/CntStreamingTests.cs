using LibProsperoPkg.PFS;
using LibProsperoPkg.PKG;
using System.Buffers.Binary;
using System.Text;
#if !STREAMING_NATIVE_TESTS
using System.Reflection;
#endif

namespace LibProsperoPkg.Tests;

internal static class CntStreamingTests
{
    private const int B = 0x10000;
    private const string ContentId = "UP9000-PPSA99099_00-PROSPERO00000000";

    internal static void Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "prospero-cnt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(folder, "sce_sys"));
        string paramPath = Path.Combine(folder, "sce_sys", "param.json");
        const string original = "{\"contentId\":\"" + ContentId + "\",\"titleName\":\"Original\",\"sdkVersion\":\"0x0000000000000000\"}";
        File.WriteAllText(paramPath, original);
        try
        {
            var props = new ProsperoPkgBuildProperties { SourceFolder = folder, ContentId = ContentId };
            var fixture = Fixture(props);
            var result = ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, fixture.Fih,
                new byte[16], 2);
            VerifyResult(result, fixture.Outer, fixture.Fih, fixture.Ciphertext);
            Program.Equal(original, File.ReadAllText(paramPath), "CNT never modifies source param");
            var overrides = new Dictionary<string, byte[]>
            {
                ["param.json"] = Encoding.UTF8.GetBytes("{\"contentId\":\"" + ContentId + "\",\"localizedParameters\":{\"defaultLanguage\":\"en-US\",\"en-US\":{\"titleName\":\"Overlay\"}},\"sdkVersion\":\"0x0000000000000000\"}"),
            };
            var overlaid = ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, fixture.Fih,
                new byte[16], 2, overrides);
            Program.Equal("Overlay", overlaid.Xml.TitleName, "SI XML uses normalized override param");
            using var bytes = new MemoryStream(overlaid.Bytes);
            var parsed = ProsperoPkgReader.Read(bytes);
            var param = parsed.Entries.Single(e => e.RawId == 0x2000);
            string packagedParam = Encoding.UTF8.GetString(overlaid.Bytes, (int)param.DataOffset, (int)param.DataSize);
            Program.Equal(true, packagedParam.Contains("Overlay"), "CNT uses override param");
            Program.Equal(true, packagedParam.Contains("0x0200000000000000"), "CNT normalizes overlay SDK baseline");
            Program.Equal(original, File.ReadAllText(paramPath), "overlay leaves original param untouched");
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, fixture.Fih, new byte[15], 2));
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, new byte[B], new byte[16], 2));
            byte[] wrongFih = fixture.Fih.ToArray(); wrongFih[0x30] ^= 1;
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, wrongFih, new byte[16], 2));
            foreach (int offset in new[] { 0x90, 0xA0, 0xA8 })
            {
                byte[] badGeometry = fixture.Fih.ToArray(); badGeometry[offset] ^= 1;
                Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, badGeometry, new byte[16], 2));
            }
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildEmbeddedContainer(props, fixture.Outer, fixture.Fih, new byte[16], 2,
                new Dictionary<string, byte[]> { ["../param.json"] = new byte[1] }));
#if !STREAMING_NATIVE_TESTS
            SharedContainerMatchesLegacy(props, fixture.Outer, fixture.Fih, fixture.Ciphertext);
#endif
        }
        finally { Directory.Delete(folder, true); }
    }

    private static (ProsperoOuterPfsStreamResult Outer, byte[] Fih, byte[] Ciphertext) Fixture(ProsperoPkgBuildProperties props)
    {
        byte[] payload = new byte[B];
        new Random(47).NextBytes(payload);
        byte[] naps = Encoding.ASCII.GetBytes("naps-fixture-only");
        using var output = new MemoryStream();
        var outer = ProsperoOuterPfsBuilder.WriteForPackage(output, new[]
        {
            new ProsperoOuterFileProducer { Name = "pfs_image.dat", WritePayload = s => { s.Write(payload); return 100L * B; } },
            new ProsperoOuterFileProducer { Name = "naps_pkg_layout.dat", Signed = true, WritePayload = s => { s.Write(naps); return null; } },
        }, new ProsperoOuterPfsBuildParameters { Seed = new byte[16] }, ProsperoPfsKeys.DeriveEkpfs(props.ContentId, props.Passcode));
        byte[] fih = ProsperoFihBuilder.BuildDebugHeader(new ProsperoFihHeaderMetadata
        {
            PfsSize = outer.PfsSize, SuperblockIndex = outer.SuperblockIndex,
            SuperblockDigest = outer.GetBlockDigest(outer.SuperblockIndex), InnerStoredBlockCount = 1,
            InnerLogicalBlockCount = 100, InnerMetadataBaseBlock = 50, NapsLength = naps.Length,
            NapsDigest = ProsperoImageDigests.Sha3_256(naps), InnerContentInodes = 7, AppFileCount = 2,
            ContentVersionHi = 0x01002003,
        });
        return (outer, fih, output.ToArray());
    }

    private static void Same(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string context)
        => Program.Equal(true, expected.SequenceEqual(actual), context);

    private static void VerifyResult(ProsperoEmbeddedCntResult result, ProsperoOuterPfsStreamResult outer,
        byte[] fih, byte[] ciphertext)
    {
        byte[] bytes = result.Bytes;
        Program.Equal(true, bytes.Length % B == 0, "CNT metadata aligned");
        Program.Equal((ulong)B, BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0x410)), "embedded FIH-relative image offset");
        Program.Equal((ulong)(B + outer.PfsSize), BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0x4b0)), "embedded CNT locator");
        Program.Equal((ulong)bytes.LongLength, BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0x4b8)), "CNT size locator");
        Program.Equal((ulong)(B + outer.PfsSize + bytes.LongLength), BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0x430)), "mount package size");
        Same(ProsperoImageDigests.ComputePackageDigest(bytes), bytes.AsSpan(0xfe0, 32), "CNT package self seal");
        byte[] signature = bytes.AsSpan(0x1000, ProsperoPkgSigner.SignatureSize).ToArray();
        Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan(0, 0x1000)), ProsperoPkgSigner.DecryptHeaderDigest(signature), "metadata RSA header seal");
        Same(outer.GetBlockDigest(outer.SuperblockIndex).Span, bytes.AsSpan(0x440, 32), "CNT captures superblock SHA3, not ICV");
        Same(ProsperoImageDigests.ComputeFixedInfoDigest(fih), bytes.AsSpan(0x460, 32), "CNT fixed-info SHA3");
        for (int i = 0; i < 2; i++)
        {
            int descriptorOffset = 0x510 + i * 8;
            int start = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(descriptorOffset)));
            int count = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(descriptorOffset + 4)));
            Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan(start, count)), bytes.AsSpan(0x520 + i * 32, 32),
                "serialized descriptor region digest");
        }
        using var mount = new MemoryStream(); mount.Write(fih); mount.Write(ciphertext); mount.Write(bytes); mount.Position = 0;
        var parsed = ProsperoPkgReader.Read(mount);
        Program.Equal(ProsperoPkgType.FullDebug, parsed.Type, "reader detects finalized image");
        Program.Equal(ContentId, parsed.Header!.ContentId, "reader resolves CNT content id");
        Program.Equal(true, ProsperoPkgValidator.Validate(parsed, ContentId).Accepted, "structural acceptance gate");
        var digestEntry = parsed.Entries.Single(e => e.RawId == 1);
        byte[] table = bytes.AsSpan((int)digestEntry.DataOffset, (int)digestEntry.DataSize).ToArray();
        var ordered = parsed.Entries.OrderBy(e => e.RawId).ToArray();
        for (int i = 0; i < ordered.Length; i++)
        {
            var entry = ordered[i];
            if (entry.RawId == 1) { Same(new byte[32], table.AsSpan(i * 32, 32), "digest table self slot zero"); continue; }
            Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan((int)entry.DataOffset, (int)entry.DataSize)),
                table.AsSpan(i * 32, 32), "every finalized CNT entry digest");
        }
        Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan((int)parsed.Header.BodyOffset, (int)parsed.Header.BodySize)),
            bytes.AsSpan(0x160, 32), "final CNT body digest");
        var imageEntry = parsed.Entries.Single(e => e.RawId == 0x40a);
        for (int i = 0; i < outer.BlockCount; i++)
        {
            byte[] digest = outer.GetBlockDigest(i).ToArray(); Array.Reverse(digest);
            Same(digest, bytes.AsSpan((int)imageEntry.DataOffset + i * 32, 32), "imagedigs on-disk reversal");
        }
        Program.Equal((long)bytes.Length, result.Xml.ContainerSize, "SI XML preserves canonical container size");
        Program.Equal(true, result.PlayGoChunkDat is { Length: > 0 }, "PlayGo descriptor returned for SI");
    }

#if !STREAMING_NATIVE_TESTS
    private static void SharedContainerMatchesLegacy(ProsperoPkgBuildProperties props, ProsperoOuterPfsStreamResult outer,
        byte[] fih, byte[] ciphertext)
    {
        var flags = BindingFlags.NonPublic | BindingFlags.Static;
        var build = typeof(ProsperoPkgBuilder).GetMethod("BuildContainer", flags)!;
        var pkg = (ProsperoCnt)build.Invoke(null, new object?[]
        {
            props, ProsperoPfsKeys.DeriveEkpfs(props.ContentId, props.Passcode), props.SourceFolder,
            (ulong)outer.PfsSize, outer.BlockCount * 32, 2u, (ulong)B, (ulong)outer.PfsSize, null, false,
        })!;
        var imageEntry = (ProsperoCntGenericEntry)pkg.Entries.Single(e => (uint)e.Id == 0x40a);
        for (int i = 0; i < outer.BlockCount; i++)
        {
            byte[] digest = outer.GetBlockDigest(i).ToArray(); Array.Reverse(digest);
            digest.CopyTo(imageEntry.FileData, i * 32);
        }
        long size = (long)pkg.Header.pfs_image_offset;
        using var legacy = new MemoryStream(); legacy.SetLength(size + ciphertext.LongLength);
        legacy.Position = size; legacy.Write(ciphertext);
        var finish = typeof(ProsperoPkgBuilder).GetMethod("FinishContainer", flags)!;
        finish.Invoke(null, new object?[]
        {
            pkg, legacy, props, fih.AsSpan(0xb0, 32).ToArray(), (long)Encoding.ASCII.GetByteCount("naps-fixture-only"), 50L,
            new ProsperoFihNwonlyFields { Ndblock = 100, InnerContentInodes = 7, AppFileCount = 2, ContentVersionHi = 0x01002003 },
            (Action<string>)(_ => { }),
        });
        byte[] expected = legacy.ToArray().AsSpan(0, (int)size).ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(expected.AsSpan(0x410), (ulong)B); // FIH wrapper's final rewrite
        var actual = ProsperoPkgBuilder.FinalizeEmbeddedContainer(pkg, props, outer, fih, new byte[16],
            new Dictionary<string, byte[]>());
        Same(expected.AsSpan(0, 0x1000), actual.Bytes.AsSpan(0, 0x1000), "shared CNT header parity without PFS readback");
        Same(expected.AsSpan(0x1000 + ProsperoPkgSigner.SignatureSize),
            actual.Bytes.AsSpan(0x1000 + ProsperoPkgSigner.SignatureSize), "shared CNT body parity without PFS readback");
        Same(ProsperoPkgSigner.DecryptHeaderDigest(expected.AsSpan(0x1000, ProsperoPkgSigner.SignatureSize).ToArray()),
            ProsperoPkgSigner.DecryptHeaderDigest(actual.Bytes.AsSpan(0x1000, ProsperoPkgSigner.SignatureSize).ToArray()),
            "random RSA seals recover identical header digest");
    }
#endif
}
