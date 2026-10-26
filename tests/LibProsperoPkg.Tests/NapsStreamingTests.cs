using LibProsperoPkg.PFS;
using LibProsperoPkg.PKG;

namespace LibProsperoPkg.Tests;

internal static class NapsStreamingTests
{
    internal static void Run()
    {
        SingleBlockMatchesLegacy();
        MixedBlockPlan();
        CoverageValidation();
        EmptyFilesHaveNoDataBlocks();
        StoredRunRebase();
        MixedMetadataBlocks();
        ReconstructTinyFile();
        ReconstructMixedAndWrappedFiles();
        LookupTablePacking();
        MultipleInodeSectors();
        LargeAuxiliaryTables();
        MetadataOnlyHighOffsets();
        ReconstructHighlyCompressedFile();
        RejectMalformedLayouts();
    }

    private static byte[] Pattern(int length)
    {
        var data = new byte[length];
        new Random(123).NextBytes(data);
        data.AsSpan(0, Math.Min(0x40000, length)).Fill(0x5a);
        return data;
    }

    private static (ProsperoPs5InnerImageLayout Layout, byte[] Image) Assemble(byte[] data,
        ProsperoInnerFilePolicy? policy = null)
    {
        using var output = new MemoryStream();
        var source = new ProsperoPs5InnerFileSource
        {
            Path = "/asset.bin", Length = data.Length,
            OpenRead = () => new MemoryStream(data, writable: false), Policy = policy,
        };
        var result = new ProsperoPs5InnerImageAssembler(1, 0).Write(output, [source]);
        return (result, output.ToArray());
    }

    private static NapsFilePlacement Placed(ProsperoPs5InnerImageLayout layout) => new()
    {
        OnDiskOffset = layout.Placements[0].OnDiskOffset,
        LogicalOffset = layout.Placements[0].LogicalOffset,
        OnDiskSize = layout.Placements[0].OnDiskSize,
        UncompressedSize = layout.Placements[0].UncompressedSize,
        StoreRaw = layout.Placements[0].StoreRaw,
        Blocks = layout.FileBlocks[0],
    };

    private static void SingleBlockMatchesLegacy()
    {
        byte[] data = Pattern(8000);
        var streamed = Assemble(data);
        var legacy = new ProsperoPs5InnerImageAssembler(1, 0).Build([
            new ProsperoPs5InnerFile { Path = "/asset.bin", Data = data },
        ]);
        byte[] expected = ProsperoNwonlyNapsGenerator.Generate(legacy);
        byte[] actual = ProsperoNwonlyNapsGenerator.Generate(streamed.Layout);
        Program.Equal(true, expected.AsSpan().SequenceEqual(actual), "one-block NAPS legacy parity");
        var parsed = ProsperoNapsLayout.Parse(actual);
        Program.Equal((int)((streamed.Layout.OutputLength + 0xffff) / 0x10000),
            parsed.Counts.NumOuterBlocks, "streamed length used without Image");
    }

    private static void MixedBlockPlan()
    {
        var result = Assemble(Pattern(0x80000 + 137));
        var records = result.Layout.FileBlocks[0];
        var plan = ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([Placed(result.Layout)], [0]);
        Program.Equal(3, records.Count, "three actual codec blocks");
        Program.Equal(3, plan.Count, "one NAPS record per actual codec block");
        Program.Equal((byte)2, plan[0].KdePredictor, "compressed first block");
        Program.Equal((long)records[0].FirstChunkCompressedSize, plan[0].EvenChunkCompressedLength,
            "real first Kraken chunk length");
        Program.Equal((byte)4, plan[1].KdePredictor, "stored full block inside compressed file");
        Program.Equal((byte)1, plan[1].Even, "full stored even flag");
        Program.Equal(0x80000L, plan[1].StreamLength, "raw encoded cursor doubles physical length");
        Program.Equal((byte)0, plan[2].KdePredictor, "stored partial tail");
        Program.Equal(137L, plan[2].StreamLength, "actual partial tail length");
        Program.Equal(result.Layout.Placements[0].OnDiskOffset + records[2].OnDiskOffset,
            plan[2].OnDiskOffset, "physical offset remains distinct from encoded cursor");
        byte[] naps = ProsperoNwonlyNapsGenerator.Generate(result.Layout);
        Program.Equal(true, naps.Length > 0, "multi-block NAPS built without image access");
    }

    private static void CoverageValidation()
    {
        NapsFilePlacement File(params ProsperoInnerPayloadBlock[] blocks) => new()
        {
            OnDiskOffset = 0, LogicalOffset = 0, OnDiskSize = 2,
            UncompressedSize = 2, StoreRaw = true, Blocks = blocks,
        };
        Program.Throws<ArgumentException>(() => ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([
            File(new ProsperoInnerPayloadBlock { OnDiskOffset = 1, LogicalOffset = 0, CompressedSize = 2, UncompressedSize = 2 })], [0]));
        Program.Throws<ArgumentException>(() => ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([
            File(new ProsperoInnerPayloadBlock { OnDiskOffset = 0, LogicalOffset = 0, CompressedSize = 1, UncompressedSize = 1 })], [0]));
        Program.Throws<ArgumentException>(() => ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([
            File(new ProsperoInnerPayloadBlock { OnDiskOffset = 0, LogicalOffset = 0, CompressedSize = 1, UncompressedSize = 2 })], [0]));
    }

    private static void EmptyFilesHaveNoDataBlocks()
    {
        var empty = Assemble([]);
        var plan = ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([Placed(empty.Layout)], [0]);
        Program.Equal(0, plan.Count, "empty file has no underflowing zero-length STD");
        var parsed = ProsperoNapsLayout.Parse(ProsperoNwonlyNapsGenerator.Generate(empty.Layout));
        Program.Equal(0L, (long)parsed.FileOffsets[0].UncompressedOffsetStart, "empty fidx preserved");
    }

    private static void StoredRunRebase()
    {
        var result = Assemble(new byte[12 * 0x40000 + 7], ProsperoInnerFilePolicy.StoreVerbatim);
        var parsed = ProsperoNapsLayout.Parse(ProsperoNwonlyNapsGenerator.Generate(result.Layout));
        Program.Equal(true, parsed.CblockInfos.Any(c => c.IsRunBase && c.TweakIdxStart == (11 * 0x40000 >> 15)),
            "stored runs rebase after eleven blocks");
    }

    private static void MixedMetadataBlocks()
    {
        var baseLayout = Assemble([1]).Layout;
        const int block = 0x40000;
        const int compressed = 101;
        var layout = new ProsperoPs5InnerImageLayout
        {
            OutputLength = baseLayout.MetadataOnDiskOffset + compressed + block,
            MetadataPlaintext = new byte[2 * block], CompressedMetadata = new byte[compressed + block],
            MetadataBlocks = [new(compressed, block, true, 50), new(block, block, false, 0x20000)],
            Nodes = baseLayout.Nodes, Ndblock = baseLayout.MetaBaseLogical / 0x10000 + 8,
            AfidLogicalOffsets = baseLayout.AfidLogicalOffsets, Placements = baseLayout.Placements,
            FileBlocks = baseLayout.FileBlocks, DataEndLogical = baseLayout.DataEndLogical,
            MetaBaseLogical = baseLayout.MetaBaseLogical,
            BlockInfoOnDiskOffset = baseLayout.BlockInfoOnDiskOffset,
            MetadataOnDiskOffset = baseLayout.MetadataOnDiskOffset,
        };
        var doc = ProsperoNapsLayout.Parse(ProsperoNwonlyNapsGenerator.Generate(layout));
        var std = doc.CblockInfos.Where(c => !c.IsRunBase).ToArray();
        Program.Equal((byte)2, std[^3].KdePredictor, "compressed metadata block");
        Program.Equal((byte)4, std[^2].KdePredictor, "stored metadata block remains stored");
        Program.Equal((byte)1, std[^2].Even, "stored metadata uses full-raw flags");
    }

    private static void ReconstructMixedAndWrappedFiles()
    {
        byte[] wrapped = new byte[4 * 0x40000 + 17];
        new Random(456).NextBytes(wrapped);
        for (int i = 0; i < 4; i++) wrapped.AsSpan(i * 0x40000, 0x18000).Fill(0x5a);
        var cases = new (byte[] Data, ProsperoInnerFilePolicy? Policy)[]
        {
            ([], null),
            (Pattern(0x80000 + 137), null),
            (new byte[12 * 0x40000 + 7], ProsperoInnerFilePolicy.StoreVerbatim),
            (wrapped, null),
        };
        foreach (var item in cases)
        {
            var result = Assemble(item.Data, item.Policy);
            byte[] naps = ProsperoNwonlyNapsGenerator.Generate(result.Layout);
            var mount = ProsperoPs5InnerImageReader.ReconstructMount(result.Image, naps,
                result.Layout.Ndblock * 0x10000);
            var files = ProsperoPs5InnerImageReader.ReadFileTree(mount.Mount, mount.SuperblockOffset);
            Program.Equal(1, files.Count, "multi-block decoded file count");
            Program.Equal((long)item.Data.Length, files[0].Size, "multi-block decoded size");
            Program.Equal(true, item.Data.AsSpan().SequenceEqual(mount.Mount.AsSpan(
                (int)files[0].LogicalOffset, (int)files[0].Size)), "every multi-block decoded byte");
            Program.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReconstructMount(
                result.Image.AsSpan(0, (int)result.Layout.MetadataOnDiskOffset + 10), naps,
                result.Layout.Ndblock * 0x10000));
        }
        var wrapLayout = Assemble(wrapped).Layout;
        var plan = ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([Placed(wrapLayout)], [0]);
        long cursor = 0;
        bool crossed = false;
        foreach (var block in plan)
        {
            long after = cursor + block.StreamLength;
            if (block.KdePredictor == 2 && (after & 0x3ffff) < (cursor & 0x3ffff)) crossed = true;
            cursor = after;
        }
        Program.Equal(true, crossed, "fixture exercises compressed cursor wrap");
    }

    private static void LookupTablePacking()
    {
        foreach (int count in new[] { 0, 1, 7, 8, 9, 16, 600 })
        {
            var blocks = Enumerable.Range(0, count).Select(i => new NapsCblockPlanEntry
            {
                StartRun = true, OnDiskOffset = (long)i * 0x40000,
                LogicalOffset = (long)i * 0x40000,
                EvenChunkCompressedLength = 0x10000, StreamLength = 0x80000,
                Even = 1, Odd = 1, KdePredictor = 4,
            }).ToList();
            blocks.Add(new NapsCblockPlanEntry
            {
                StartRun = true, Terminator = true,
                LogicalOffset = (long)count * 0x40000, OnDiskOffset = (long)count * 0x40000,
            });
            var document = ProsperoNapsLayoutBuilder.BuildDocument(new NapsGenerationRequest
            {
                NumUBlocks = count, NumOuterBlocks = count,
                FileLogicalOffsets = [0, (long)count * 0x40000], Blocks = blocks,
            });
            // Inspect parsed bytes, not only the in-memory model or the reader (which does not use u2c).
            var parsed = ProsperoNapsLayout.Parse(ProsperoNapsLayout.BuildLayout(document));
            uint terminator = (uint)(2 * count + 1);
            Program.Equal((count + 8) >> 3, parsed.CblockInfoOffsetByUblock.Count, "u2c group count");
            for (int g = 0; g < parsed.CblockInfoOffsetByUblock.Count; g++)
            for (int j = 0; j < 8; j++)
            {
                int ublock = g * 8 + j;
                uint expected = ublock < count ? (uint)(2 * ublock + 1) : terminator;
                Program.Equal(expected, parsed.CblockInfoOffsetByUblock[g].StartCblockInfoIndex[j],
                    "u2c points to expected STD or terminator");
            }
            if (count == 600)
                Program.Equal(true, parsed.CblockInfoOffsetByUblock.Any(e => e.InfoOffset9BBase > 255),
                    "u2c preserves full 24-bit base");
        }
        byte[] encoded = ProsperoNapsLayout.EncodeU2cEntry(new NapsU2cEntry(0x123456, [1, 2, 3, 4, 5, 6, 7]));
        Program.Equal(true, encoded.AsSpan().SequenceEqual(new byte[] { 0x56, 0x34, 0x12, 1, 2, 3, 4, 5, 6, 7 }),
            "hand-specified uint24/seven-delta encoding");
    }

    private static void MultipleInodeSectors()
    {
        var sources = Enumerable.Range(0, 473).Select(i => new ProsperoPs5InnerFileSource
        {
            Path = "/f" + i, Length = 1,
            OpenRead = () => new MemoryStream(new byte[] { 0x5a }),
        }).ToArray();
        using var bytes = new MemoryStream();
        var layout = new ProsperoPs5InnerImageAssembler(1, 0).Write(bytes, sources);
        Program.Equal(478, layout.Nodes.Count, "more than one inode sector");
        Program.Equal(2L, System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(
            layout.MetadataPlaintext.AsSpan(0x40)), "superblock declares complete inode sector count");
        // Independently walk final plaintext metadata; constructing NAPS for very dense tiny files
        // remains limited by the format's byte-sized per-group deltas.
        var mount = new byte[checked((int)(layout.Ndblock * 0x10000))];
        layout.MetadataPlaintext.CopyTo(mount, (int)layout.MetaBaseLogical);
        var entries = ProsperoPs5InnerImageReader.ReadFileTree(mount, layout.MetaBaseLogical);
        Program.Equal(473, entries.Count, "all file inodes survive sector boundaries");
        Program.Equal(true, entries.Any(e => e.Path == "f472" && e.Size == 1), "final inode remains readable");
    }

    private static void LargeAuxiliaryTables()
    {
        var sources = Enumerable.Range(0, 5000).Select(i => new ProsperoPs5InnerFileSource
        {
            Path = "/f" + i, Length = 1, OpenRead = () => new MemoryStream(new byte[] { 0x5a }),
        }).ToArray();
        using var bytes = new MemoryStream();
        var layout = new ProsperoPs5InnerImageAssembler(1, 0).Write(bytes, sources);
        Program.Equal(true, layout.Nodes.Single(n => n.Name == "inode_flat_path_table").Size > 0x10000,
            "inode flat-path table spans multiple sectors");
        Program.Equal(true, layout.Nodes.Single(n => n.Name == "apr_flat_path_table").Size > 0x10000,
            "application flat-path table spans multiple sectors");
        var mount = new byte[checked((int)(layout.Ndblock * 0x10000))];
        layout.MetadataPlaintext.CopyTo(mount, (int)layout.MetaBaseLogical);
        var files = ProsperoPs5InnerImageReader.ReadFileTreeFromMetadata(layout.MetadataPlaintext, layout.MetaBaseLogical);
        Program.Equal(5000, files.Count, "all files survive multi-sector tables and directory");
        Program.Equal(true, files.Any(f => f.Path == "f4999" && f.Size == 1), "last wide-directory file readable");
        foreach (var directory in layout.Nodes.Where(n => n.IsDirectory))
        {
            int start = checked((int)((long)directory.LogicalOffset - layout.MetaBaseLogical));
            for (int sector = 0; sector < directory.Size; sector += 0x10000)
            {
                int position = 0;
                while (position + 16 <= 0x10000)
                {
                    var header = layout.MetadataPlaintext.AsSpan(start + sector + position, 16);
                    if (header.IndexOfAnyExcept((byte)0) < 0) break;
                    int size = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header[12..]);
                    Program.Equal(true, size >= 24 && position + size <= 0x10000,
                        "every directory entry fits entirely in its sector");
                    position += size;
                }
            }
        }
        var lastFile = layout.Nodes.Single(n => n.Name == "f4999");
        var parent = layout.Nodes.Single(n => n.Inode == lastFile.ParentInode);
        int parentEntry = checked((int)((long)parent.LogicalOffset - layout.MetaBaseLogical) + lastFile.DirentOffset);
        Program.Equal(lastFile.Inode, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
            layout.MetadataPlaintext.AsSpan(parentEntry)), "parent dirent offset accounts for sector padding");
        var serializer = new ProsperoPs5InnerMetadata(1, 0);
        ulong offset = 400UL * 1024 * 1024 * 1024 + 123;
        byte[] image = serializer.Build([new ProsperoPs5MetaNode { LogicalOffset = offset }], 1, []);
        Program.Equal(offset, System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(
            image.AsSpan(0x10000 + 0x60)), "logical offsets retain their high 32 bits");
    }

    private static void MetadataOnlyHighOffsets()
    {
        var layout = Assemble([1]).Layout;
        byte[] metadata = (byte[])layout.MetadataPlaintext.Clone();
        const long delta = 400L * 1024 * 1024 * 1024;
        for (int i = 0; i < layout.Nodes.Count; i++)
        {
            int position = 0x10000 + (i / ProsperoPs5InnerMetadata.InodesPerBlock) * 0x10000
                + (i % ProsperoPs5InnerMetadata.InodesPerBlock) * ProsperoPs5InnerMetadata.InodeSize + 0x60;
            ulong original = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(metadata.AsSpan(position));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(metadata.AsSpan(position), original + delta);
        }
        var files = ProsperoPs5InnerImageReader.ReadFileTreeFromMetadata(metadata, layout.MetaBaseLogical + delta);
        Program.Equal(1, files.Count, "metadata-only high-offset catalog");
        Program.Equal((ulong)delta, files[0].LogicalOffset, "file retains 400 GiB logical offset without mount allocation");
        Program.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReadFileTreeFromMetadata(
            metadata.AsSpan(0, 0x10000).ToArray(), layout.MetaBaseLogical + delta));
    }

    private static void ReconstructHighlyCompressedFile()
    {
        byte[] source = new byte[8 * 1024 * 1024];
        source.AsSpan().Fill(0x5a);
        var result = Assemble(source);
        Program.Equal(true, result.Layout.MetaBaseLogical > result.Layout.DataEndLogical,
            "metadata logical address follows uncompressed data");
        byte[] naps = ProsperoNwonlyNapsGenerator.Generate(result.Layout);
        var mount = ProsperoPs5InnerImageReader.ReconstructMount(result.Image, naps,
            result.Layout.Ndblock * 0x10000);
        var entries = ProsperoPs5InnerImageReader.ReadFileTree(mount.Mount, mount.SuperblockOffset);
        Program.Equal(true, source.AsSpan().SequenceEqual(mount.Mount.AsSpan(
            (int)entries[0].LogicalOffset, (int)entries[0].Size)), "highly compressed source round-trip");
    }

    private static void RejectMalformedLayouts()
    {
        var result = Assemble(Pattern(8000));
        byte[] damaged = (byte[])result.Layout.MetadataPlaintext.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(damaged.AsSpan(0x30), 0x100000005);
        Program.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReadFileTreeFromMetadata(
            damaged, result.Layout.MetaBaseLogical));
        var rootNode = result.Layout.Nodes.Single(n => n.Name == "uroot");
        int directoryStart = checked((int)((long)rootNode.LogicalOffset - result.Layout.MetaBaseLogical));
        int firstFile = directoryStart + 48; // two 24-byte dot entries
        foreach (int field in new[] { 0, 8, 12 })
        {
            damaged = (byte[])result.Layout.MetadataPlaintext.Clone();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(damaged.AsSpan(firstFile + field), int.MaxValue);
            Program.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReadFileTreeFromMetadata(
                damaged, result.Layout.MetaBaseLogical));
        }
        var parsed = ProsperoNapsLayout.Parse(ProsperoNwonlyNapsGenerator.Generate(result.Layout));
        byte[] Mutate(Func<NapsCblockInfoEntry, NapsCblockInfoEntry> change, int index)
        {
            var entries = parsed.CblockInfos.ToArray();
            entries[index] = change(entries[index]);
            return ProsperoNapsLayout.BuildLayout(new NapsLayoutDocument
            {
                Counts = parsed.Counts, Map = parsed.Map,
                OuterBlockDigests = parsed.OuterBlockDigests, ShufflePatterns = parsed.ShufflePatterns,
                FileOffsets = parsed.FileOffsets, CblockInfoOffsetByUblock = parsed.CblockInfoOffsetByUblock,
                CblockInfos = entries,
            });
        }
        int firstData = parsed.CblockInfos.Select((e, i) => (e, i)).First(v => !v.e.IsRunBase).i;
        byte[] early = Mutate(e => e with { Even = 0, Odd = 0 }, firstData);
        Program.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReconstructMount(
            result.Image, early, result.Layout.Ndblock * 0x10000));
        byte[] unsupported = Mutate(e => e with { KdePredictor = 7 }, firstData);
        Program.Throws<NotSupportedException>(() => ProsperoPs5InnerImageReader.ReconstructMount(
            result.Image, unsupported, result.Layout.Ndblock * 0x10000));
        byte[] missingEnd = Mutate(e => e with { Odd = 1 }, parsed.CblockInfos.Count - 1);
        Program.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReconstructMount(
            result.Image, missingEnd, result.Layout.Ndblock * 0x10000));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoNapsLayout.EncodeHeader(
            new NapsLayoutCounts(1, 2, 1, 0, 1, 0x1000000, 2)));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoNapsLayout.EncodeFileOffsetEntry(
            new NapsFileOffsetEntry(0, 1UL << 40)));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoNapsLayout.EncodeU2cEntry(
            new NapsU2cEntry(0x1000000, [])));
        Program.Throws<ArgumentOutOfRangeException>(() => ProsperoNapsLayout.EncodeCblockInfoEntry(
            new NapsCblockInfoEntry { IsRunBase = true, CoffsetStart256K = 0x1000000 }));
        var partial = new NapsFilePlacement
        {
            OnDiskOffset = 0, LogicalOffset = 0, OnDiskSize = 200, UncompressedSize = 200,
            StoreRaw = true,
            Blocks = [new() { UncompressedSize = 100, CompressedSize = 100 },
                new() { LogicalOffset = 100, OnDiskOffset = 100, UncompressedSize = 100, CompressedSize = 100 }],
        };
        Program.Throws<ArgumentException>(() => ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([partial], [0]));
        foreach (int hint in new[] { -1, 99 })
        {
            var badChunks = new NapsFilePlacement
            {
                OnDiskOffset = 0, LogicalOffset = 0, OnDiskSize = 100, UncompressedSize = 0x40000,
                StoreRaw = false, Blocks = [new() { UncompressedSize = 0x40000, CompressedSize = 100, SizeHint = hint }],
            };
            Program.Throws<ArgumentException>(() => ProsperoNapsLayoutBuilder.DeriveDataRegionBlocks([badChunks], [0]));
        }
    }

    private static void ReconstructTinyFile()
    {
        byte[] source = Pattern(8000);
        var result = Assemble(source);
        byte[] naps = ProsperoNwonlyNapsGenerator.Generate(result.Layout);
        var mount = ProsperoPs5InnerImageReader.ReconstructMount(result.Image, naps,
            result.Layout.Ndblock * 0x10000);
        var entries = ProsperoPs5InnerImageReader.ReadFileTree(mount.Mount, mount.SuperblockOffset);
        Program.Equal(result.Layout.MetaBaseLogical, mount.SuperblockOffset, "reconstructed metadata base");
        Program.Equal(1, entries.Count, "reconstructed file count");
        Program.Equal("asset.bin", entries[0].Path, "reconstructed file path");
        Program.Equal(true, source.AsSpan().SequenceEqual(mount.Mount.AsSpan(
            (int)entries[0].LogicalOffset, (int)entries[0].Size)), "every reconstructed source byte");
    }
}
