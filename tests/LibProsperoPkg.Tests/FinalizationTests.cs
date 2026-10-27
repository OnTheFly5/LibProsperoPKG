using LibProsperoPkg.PFS;
using LibProsperoPkg.PKG;
using LibProsperoPkg.PlayGo;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibProsperoPkg.Tests;

internal static class FinalizationTests
{
    private const int B = 0x10000;
    internal static void Run()
    {
        MountHashes();
        MountFailures();
        FihAndSiFromMetadata();
        HeaderGeometry();
    }
    private static void Same(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string context)
        => Program.Equal(true, expected.SequenceEqual(actual), context);

    private static void MountHashes()
    {
        foreach (int length in new[] { 1, B - 1, B, B + 1, B * 3 + 7 })
        {
            byte[] bytes = new byte[length + 11];
            new Random(42).NextBytes(bytes);
            using var source = new ShortReader(new MemoryStream(bytes));
            var result = ProsperoFinalizedMountDigests.Compute(source, length,
                length >= B ? 0 : null, captureBlockDigests: true);
            Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan(0, length)), result.MountDigest.Span, "mount SHA3 exactly excludes trailing SI");
            Same(ProsperoPlayGo.BuildChunkCrc(bytes.AsSpan(0, length)), result.PlayGoChunkCrc.Span, "incremental CRC actual partial tail");
            Program.Equal((long)length, source.ReadCount, "mount reads exact length");
            Program.Equal(true, source.CanRead, "source remains open");
            Program.Equal(true, source.MaxRead <= B, "mount payload read window");
            for (int i = 0; i * B < length; i++)
                Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan(i * B, Math.Min(B, length - i * B))),
                    result.GetBlockDigest(i).Span, "optional on-disk block hashes");
            if (length >= B)
                Same(ProsperoImageDigests.Sha3_256(bytes.AsSpan(0, B)), result.SuperblockDigest.Span, "explicit root hash");
            else Same(new byte[32], result.SuperblockDigest.Span, "no root has zero slot");
            var imported = new ProsperoFinalizedMountDigests(length, result.MountDigest.Span,
                result.SuperblockDigest.Span, result.PlayGoChunkCrc.Span);
            Same(result.MountDigest.Span, imported.MountDigest.Span, "external digest contract");
            Program.Equal(false, imported.HasBlockDigests, "remote metadata needs no full block hash table");
            Program.Throws<InvalidOperationException>(() => imported.GetBlockDigest(0));
        }
    }

    private static void MountFailures()
    {
        using var source = new ShortReader(new MemoryStream(new byte[B]));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoFinalizedMountDigests.Compute(source, 0));
        Program.Throws<NotSupportedException>(() => ProsperoFinalizedMountDigests.Compute(source, long.MaxValue));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoFinalizedMountDigests.Compute(source, B, 1));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoFinalizedMountDigests.Compute(source, B, B));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoFinalizedMountDigests.Compute(source, B, -B));
        Program.Equal(0L, source.ReadCount, "bad geometry fails before source reads");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Program.Throws<OperationCanceledException>(() => ProsperoFinalizedMountDigests.Compute(source, B,
            cancellationToken: cancelled.Token));
        Program.Throws<EndOfStreamException>(() => ProsperoFinalizedMountDigests.Compute(source, B + 1));
        Program.Equal(true, source.CanRead, "short source stays caller owned");
        Program.Throws<ArgumentException>(() => new ProsperoFinalizedMountDigests(B, new byte[31], new byte[32], new byte[4]));
        Program.Throws<ArgumentException>(() => new ProsperoFinalizedMountDigests(B + 1, new byte[32], new byte[32], new byte[4]));
    }

    private static void FihAndSiFromMetadata()
    {
        byte[] raw = new byte[0x80000 + 7];
        new Random(43).NextBytes(raw);
        raw.AsSpan(0, 0x40000).Fill(0x55);
        var files = new[]
        {
            new ProsperoPs5InnerFile { Path = "/sce_sys/keystone", Data = new byte[96] },
            new ProsperoPs5InnerFile { Path = "/asset.bin", Data = raw },
            new ProsperoPs5InnerFile { Path = "/empty", Data = Array.Empty<byte>() },
        };
        var assembler = new ProsperoPs5InnerImageAssembler(12345678, 0);
        var inner = assembler.Build(files);
        using var innerOutput = new MemoryStream();
        var streamed = assembler.Write(innerOutput, files.Select(f => new ProsperoPs5InnerFileSource
        {
            Path = f.Path, Length = f.Data.LongLength, OpenRead = () => new ShortReader(new MemoryStream(f.Data)),
        }).ToArray());
        byte[] naps = ProsperoNwonlyNapsGenerator.Generate(inner);
        byte[] napsHash = ProsperoImageDigests.Sha3_256(naps);
        var outer = ProsperoOuterPfsBuilder.BuildForPackage(new[]
        {
            new ProsperoOuterFile { Name = "pfs_image.dat", Data = inner.Image, SizeCompressed = inner.Ndblock * B },
            new ProsperoOuterFile { Name = "naps_pkg_layout.dat", Data = naps, Signed = true },
        }, new ProsperoOuterPfsBuildParameters { Seed = new byte[16] }, new byte[32]);
        long innerBlocks = (inner.OutputLength + B - 1) / B;
        var metadata = Header(outer.PfsSize, outer.SuperblockIndex, innerBlocks, naps.Length,
            inner.Ndblock, inner.MetaBaseLogical / B, outer.ImageDigests.AsMemory(outer.SuperblockIndex * 32, 32), napsHash);
        byte[] fih = ProsperoFihBuilder.BuildDebugHeader(metadata);
        Program.Equal("DC9915E6A86E9E6197BD59A8C69C41FF30E104EDFBCA95FD23910ECE054028E5",
            Convert.ToHexString(SHA256.HashData(fih)), "pinned FIH fixture from bc961cf");
#if !STREAMING_NATIVE_TESTS
        byte[] legacy = ProsperoFihBuilder.BuildFihHeaderBlock(ProsperoFihVariant.Debug,
            (ulong)outer.PfsSize, (ulong)(B + outer.PfsSize), outer.Ciphertext,
            nestedImageDigest: napsHash, nestedImageSize: naps.Length, nestedMetaBaseBlocks: inner.MetaBaseLogical / B,
            nwonlyContentVersionHi: metadata.ContentVersionHi, nwonlyInnerContentInodes: metadata.InnerContentInodes,
            nwonlyAppFileCount: metadata.AppFileCount, nwonlyNdblock: inner.Ndblock);
        Same(legacy, fih, "full FIH parity for existing profile");
#endif
        using var mount = new MemoryStream();
        mount.Write(fih);
        mount.Write(outer.Ciphertext);
        mount.Write(new byte[B]); // controlled CNT-sized suffix; this is not a complete package fixture
        byte[] finalBytes = mount.ToArray();
        mount.Position = 0;
        var digests = ProsperoFinalizedMountDigests.Compute(mount, mount.Length,
            (outer.SuperblockIndex + 1L) * B);
        var contentFiles = files.Select(f => (f.Path.TrimStart('/'), f.Data.LongLength)).ToList();
        contentFiles.Add(("*PFSmetadata", outer.PfsSize));
        ulong physicalSiSize = (ulong)innerBlocks * B; // Existing SI caller uses aligned physical size, not FIH logical size.
        Program.Equal(false, innerBlocks == inner.Ndblock, "SI physical size differs from FIH logical size");
        byte[] expected = ProsperoNapsMeta.BuildMeta18(physicalSiSize, finalBytes, contentFiles, inner);
        byte[] actual = ProsperoNapsMeta.BuildMeta18FromDigests(physicalSiSize, digests, contentFiles, streamed);
        Same(expected, actual, "encrypted SI parity without inner/mount images");
        var xml = new ProsperoPfsImageXmlOptions
        {
            ContentId = "UP9000-PPSA99099_00-PROSPERO00000000", PfsImageSize = outer.PfsSize,
            NestedInner = inner,
        };
        byte[] legacyZip = ProsperoSiArchive.BuildDebugSiSegment(xml, null, finalBytes, (long)physicalSiSize);
        xml.NestedInnerLayout = streamed;
        byte[] streamedZip = ProsperoSiArchive.BuildDebugSiSegmentFromDigests(xml, null, digests);
        Same(legacyZip, streamedZip, "complete SI ZIP parity using only layout and hashes");
        Same(legacyZip, ProsperoSiArchive.BuildDebugSiSegment(xml, null, finalBytes, (long)physicalSiSize),
            "array SI adapter honors streamed inner layout");
        Program.Equal(false, digests.HasBlockDigests, "nwonly SI does not need duplicate mount block digests");
        byte[] goldenMount = new byte[3 * B + 7];
        new Random(45).NextBytes(goldenMount);
        using var goldenSource = new MemoryStream(goldenMount);
        var goldenHashes = ProsperoFinalizedMountDigests.Compute(goldenSource, goldenMount.Length);
        var goldenContent = files.Select(f => (f.Path.TrimStart('/'), f.Data.LongLength)).ToList();
        goldenContent.Add(("*PFSmetadata", goldenMount.LongLength));
        byte[] goldenSi = ProsperoNapsMeta.BuildMeta18FromDigests(physicalSiSize, goldenHashes, goldenContent, streamed);
        // Independently generated at pinned bc961cf, before this finalization refactor.
        Program.Equal("0E786BC281CD67DA9878C89A18743AB21720B4054CA8726F2D5D98BCB4AFFDE9",
            Convert.ToHexString(SHA256.HashData(goldenSi)), "pinned encrypted SI fixture");
        Program.Throws<ArgumentException>(() => ProsperoNapsMeta.BuildMeta18FromDigests(physicalSiSize + B,
            digests, contentFiles, streamed));
        var badExtent = new ProsperoPs5InnerImageLayout
        {
            Ndblock = streamed.Ndblock, MetadataPlaintext = streamed.MetadataPlaintext,
            Nodes = streamed.Nodes, AfidLogicalOffsets = streamed.AfidLogicalOffsets,
            OutputLength = streamed.OutputLength, CompressedMetadata = streamed.CompressedMetadata,
            MetadataOnDiskOffset = streamed.MetadataOnDiskOffset, MetadataBlocks = streamed.MetadataBlocks,
            MetaBaseLogical = streamed.MetaBaseLogical, DataEndLogical = streamed.DataEndLogical,
            FileDigests = new[] { streamed.FileDigests[0] },
            Placements = new[] { new ProsperoPs5InnerPlacement
            {
                OnDiskOffset = streamed.OutputLength, OnDiskSize = 1, UncompressedSize = 1,
            } },
        };
        Program.Throws<ArgumentException>(() => ProsperoNapsMeta.BuildMeta18FromDigests(physicalSiSize,
            digests, contentFiles, badExtent));
        for (int i = 0; i < streamed.Placements.Count; i++)
        {
            var p = streamed.Placements[i];
            Same(ProsperoImageDigests.Sha3_256(inner.Image.AsSpan((int)p.OnDiskOffset, (int)p.OnDiskSize)),
                streamed.FileDigests[i].Span, "whole encoded extent digest captured during first pass");
        }
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoNapsMeta.BuildMeta18FromDigests(1UL << 32, digests, contentFiles, streamed));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoNapsMeta.BuildMeta18FromDigests(physicalSiSize + 1, digests, contentFiles, streamed));
        // Changes in each mount segment affect obdg; bytes appended after the mount do not enter it.
        foreach (int offset in new[] { 0, B + 17, finalBytes.Length - 1 })
        {
            byte[] changed = finalBytes.ToArray();
            changed[offset] ^= 1;
            using var reader = new MemoryStream(changed);
            var changedDigest = ProsperoFinalizedMountDigests.Compute(reader, changed.LongLength);
            Program.Equal(false, changedDigest.MountDigest.Span.SequenceEqual(digests.MountDigest.Span), "finalized mount mutations detected");
        }
        using var noRoot = new MemoryStream(finalBytes);
        var identityHashes = ProsperoFinalizedMountDigests.Compute(noRoot, finalBytes.Length, captureBlockDigests: true);
        Program.Equal(true, identityHashes.HasBlockDigests, "legacy identity-map capture available");
    }

    private static ProsperoFihHeaderMetadata Header(long size, long sb, long stored, long naps,
        long logical = 100, long metaBase = 50, ReadOnlyMemory<byte> root = default, ReadOnlyMemory<byte> hash = default)
        => new()
        {
            PfsSize = size, SuperblockIndex = sb, InnerStoredBlockCount = stored,
            NapsLength = naps, InnerLogicalBlockCount = logical, InnerMetadataBaseBlock = metaBase,
            SuperblockDigest = root.IsEmpty ? new byte[32] : root,
            NapsDigest = hash.IsEmpty ? new byte[32] : hash,
            InnerContentInodes = 7, AppFileCount = 2, ContentVersionHi = 0x01002003,
        };

    private static void HeaderGeometry()
    {
        byte[] first = ProsperoFihBuilder.BuildDebugHeader(Header(20L * B, 15, 14, B));
        byte[] second = ProsperoFihBuilder.BuildDebugHeader(Header(21L * B, 16, 14, B + 1));
        Program.Equal(14U, BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(0x90)), "one-block NAPS physical inner count");
        Program.Equal(14U, BinaryPrimitives.ReadUInt32LittleEndian(second.AsSpan(0x90)), "multi-block NAPS leaves inner count unchanged");
        Program.Equal(17UL * B, BinaryPrimitives.ReadUInt64LittleEndian(second.AsSpan(0x20)), "superblock absolute offset");
        Program.Equal(100UL * B, BinaryPrimitives.ReadUInt64LittleEndian(second.AsSpan(0xa0)), "logical size independent from physical");
        Program.Equal(50UL, BinaryPrimitives.ReadUInt64LittleEndian(second.AsSpan(0x50)), "metadata base is not Ndblock");
        Program.Equal((ulong)B + 1, BinaryPrimitives.ReadUInt64LittleEndian(second.AsSpan(0xa8)), "NAPS exact unpadded length");
        Program.Equal(7U, BinaryPrimitives.ReadUInt32LittleEndian(second.AsSpan(0x94)), "content inode count");
        Program.Equal(0x01002003U, BinaryPrimitives.ReadUInt32LittleEndian(second.AsSpan(0x9c)), "content version echo");
        const long large = 400L * 1024 * 1024 * 1024;
        byte[] largeHeader = ProsperoFihBuilder.BuildDebugHeader(Header(large + 6L * B, large / B + 1, large / B, B,
            large / B + 100, large / B + 50));
        Program.Equal((ulong)large + 6UL * B, BinaryPrimitives.ReadUInt64LittleEndian(largeHeader.AsSpan(0x18)), "400 GiB scalar geometry without payload allocation");
        foreach (var bad in new[]
        {
            Header(0, 15, 14, B), Header(20L * B + 1, 15, 14, B), Header(20L * B, 16, 14, B),
            Header(20L * B, 15, 14, B + 1), Header(20L * B, 15, 0, B),
            Header(20L * B, 15, 14, B, logical: -1), Header(20L * B, 15, 14, B, metaBase: 100),
            Header(20L * B, 15, 14, B, root: new byte[31]), Header(20L * B, 15, 14, B, hash: new byte[33]),
        }) Program.Throws<ArgumentException>(() => ProsperoFihBuilder.BuildDebugHeader(bad));
    }

    private sealed class ShortReader(Stream source) : Stream
    {
        internal long ReadCount { get; private set; }
        internal int MaxRead { get; private set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            MaxRead = Math.Max(MaxRead, count);
            int n = source.Read(buffer, offset, Math.Min(count, 997));
            ReadCount += n;
            return n;
        }
        public override bool CanRead => source.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
