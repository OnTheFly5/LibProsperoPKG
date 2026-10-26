using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using System.Security.Cryptography;

namespace LibProsperoPkg.Tests;

internal static class StreamingTests
{
    internal static void Run()
    {
        PayloadMatchesReference();
        DeferredPrefixMatchesReference();
        InnerImageMatchesReference();
        FolderInputIsReadOnce();
        InvalidSourcesAndCancellation();
        BoundedPayloadAllocation();
    }

    private static byte[] Pattern(int length)
    {
        var data = new byte[length];
        new Random(42).NextBytes(data);
        // One compressible full block, followed by incompressible data and a partial tail.
        data.AsSpan(0, Math.Min(data.Length, 0x40000)).Fill(0x5a);
        return data;
    }

    private static void Same(byte[] expected, byte[] actual, string context)
        => Program.Equal(true, expected.AsSpan().SequenceEqual(actual), context);

    private static void PayloadMatchesReference()
    {
        foreach (int length in new[] { 0, 1, 257, 0x20000, 0x40000, 0x80000 + 137 })
        foreach (bool raw in new[] { false, true })
        {
            byte[] data = Pattern(length);
            byte[] expected = ProsperoPs5InnerImageBuilder.CompressPayload(data, raw, out var parsed);
            using var source = new ForwardReader(new MemoryStream(data), maxRead: 997);
            using var bytes = new MemoryStream();
            using var output = new ForwardWriter(bytes);
            var result = ProsperoPs5InnerImageBuilder.WritePayload(output, source, length, raw);
            Same(expected, bytes.ToArray(), $"payload length={length} raw={raw}");
            Program.Equal((long)expected.Length, result.Length, "payload encoded length");
            Program.Equal((long)length, result.Blocks.Sum(b => (long)b.UncompressedSize), "block logical coverage");
            if (parsed is not null)
            {
                Program.Equal(parsed.Blocks.Count, result.Blocks.Count, "compression block count");
                for (int i = 0; i < parsed.Blocks.Count; i++)
                {
                    Program.Equal(parsed.Blocks[i].CompressedSize, result.Blocks[i].CompressedSize, "block encoded size");
                    Program.Equal(parsed.Blocks[i].IsMultiChunk, result.Blocks[i].IsMultiChunk, "block subchunk form");
                    Program.Equal(parsed.Blocks[i].FirstChunkCompressedSize,
                        result.Blocks[i].FirstChunkCompressedSize, "subchunk size");
                }
            }
            byte[] emitted = bytes.ToArray();
            foreach (var block in result.Blocks)
                Same(ProsperoPfsDigest.ComputeBlockDigest(emitted.AsSpan((int)block.OnDiskOffset,
                    block.CompressedSize)), block.OnDiskDigest.ToArray(), "encoded block digest");
            Program.Equal(false, output.Sought, "payload output never seeks");
        }
    }

    private static void DeferredPrefixMatchesReference()
    {
        foreach (bool compress in new[] { false, true })
        foreach (int length in new[] { 0, 257, 0x80000 + 137 })
        {
            byte[] input = Pattern(length);
            byte[] expected = compress
                ? ProsperoCompressedPfsFileWriter.WriteCompressed(input)
                : ProsperoCompressedPfsFileWriter.WriteStored(input);
            using var source = new ForwardReader(new MemoryStream(input), 113);
            using var bytes = new MemoryStream();
            // The container may begin at a nonzero destination offset.
            bytes.Write(new byte[] { 1, 2, 3 });
            using var output = new ForwardWriter(bytes);
            var result = ProsperoCompressedPfsFileWriter.WriteDeferred(output, source, length, compress);
            Program.Equal((long)expected.Length, result.Length, "deferred container length");
            Program.Equal(true, bytes.ToArray().AsSpan(3, result.Prefix.Length).IndexOfAnyExcept((byte)0) < 0,
                "prefix reserved with real zero bytes");
            // Simulate bounded PWRITE calls after completing the sequential stream.
            byte[] actual = bytes.ToArray();
            for (int offset = 0; offset < result.Prefix.Length; offset += 1024)
            {
                int count = Math.Min(1024, result.Prefix.Length - offset);
                result.Prefix.Span.Slice(offset, count).CopyTo(actual.AsSpan(3 + offset));
            }
            Same(expected, actual[3..], "deferred prefix patches reproduce reference container");
            Same(new byte[] { 1, 2, 3 }, actual[..3], "patch preserves leading output bytes");
            var parsed = ProsperoCompressedPfsFile.Parse(actual[3..]);
            Program.Equal((long)length, parsed.UncompressedSize, "patched container parses");
        }
    }

    private static void InnerImageMatchesReference()
    {
        byte[] module = Pattern(0x10000 + 17);
        new byte[] { 0x54, 0x14, 0xf5, 0xee }.CopyTo(module, 0);
        var files = new[]
        {
            new ProsperoPs5InnerFile { Path = "/sce_sys/keystone", Data = Pattern(96) },
            new ProsperoPs5InnerFile { Path = "/sce_module/lib.prx", Data = module },
            new ProsperoPs5InnerFile { Path = "/a/asset.dat", Data = Pattern(0x80000 + 137) },
            new ProsperoPs5InnerFile { Path = "/z/empty", Data = [] },
            new ProsperoPs5InnerFile { Path = "/root.bin", Data = Pattern(91) },
        };
        var assembler = new ProsperoPs5InnerImageAssembler(12345678, 123);
        var reference = assembler.Build(files);
        // Generated independently from the pinned db8510e library, before the streaming changes.
        Program.Equal("15D59C177555C0E6565A5BE6C6BB7D88B66994962277F3D1A1B62944E35F03C1",
            Convert.ToHexString(SHA256.HashData(reference.Image)), "pinned legacy inner-image fixture");
        int opened = 0;
        var sources = files.Select(f => new ProsperoPs5InnerFileSource
        {
            Path = f.Path, Length = f.Data.LongLength,
            OpenRead = () => { opened++; return new ForwardReader(new MemoryStream(f.Data), 13); },
        }).ToArray();
        using var bytes = new MemoryStream();
        using var output = new ForwardWriter(bytes);
        var streamed = assembler.Write(output, sources);
        Same(reference.Image, bytes.ToArray(), "inner image is byte-identical");
        Same(reference.MetadataPlaintext, streamed.MetadataPlaintext, "metadata byte-identical");
        Program.Equal(files.Length, opened, "each source opens once");
        Program.Equal(reference.Image.LongLength, streamed.OutputLength, "inner output length");
        Program.Equal(reference.Ndblock, streamed.Ndblock, "mount geometry");
        Program.Equal(reference.BlockInfoOnDiskOffset, streamed.BlockInfoOnDiskOffset, "block info offset");
        Program.Equal(reference.MetadataOnDiskOffset, streamed.MetadataOnDiskOffset, "metadata offset");
        for (int i = 0; i < reference.Placements.Count; i++)
        {
            Program.Equal(reference.Placements[i].OnDiskOffset, streamed.Placements[i].OnDiskOffset, "file offset");
            Program.Equal(reference.Placements[i].OnDiskSize, streamed.Placements[i].OnDiskSize, "file disk size");
            Program.Equal(reference.Placements[i].UncompressedSize, streamed.Placements[i].UncompressedSize, "file logical size");
            Program.Equal(reference.Placements[i].StoreRaw, streamed.Placements[i].StoreRaw, "file policy");
        }
        Program.Equal(false, output.Sought, "inner output never seeks");
    }

    private static void FolderInputIsReadOnce()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-stream-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string sourcePath = Path.Combine(root, "source.bin");
            byte[] original = Pattern(0x40000 + 7);
            File.WriteAllBytes(sourcePath, original);
            int opens = 0;
            string outputPath = Path.Combine(root, "inner.pfs");
            using (var file = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write))
            using (var output = new ForwardWriter(file))
            {
                var source = new ProsperoPs5InnerFileSource
                {
                    Path = "/source.bin", Length = original.Length,
                    OpenRead = () => { opens++; return File.OpenRead(sourcePath); },
                };
                var result = new ProsperoPs5InnerImageAssembler(1, 0).Write(output, [source]);
                Program.Equal(result.OutputLength, file.Length, "explicit local output length");
            }
            Program.Equal(1, opens, "filesystem source opens once");
            Same(original, File.ReadAllBytes(sourcePath), "source file unchanged");
            Program.Equal(2, Directory.GetFiles(root).Length, "no intermediate files created");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void InvalidSourcesAndCancellation()
    {
        var assembler = new ProsperoPs5InnerImageAssembler(1, 0);
        ProsperoPs5InnerFileSource Source(string path, long length = 1, byte[]? data = null) => new()
        {
            Path = path, Length = length,
            OpenRead = () => new ForwardReader(new MemoryStream(data ?? new byte[] { 1 }), 1),
        };
        foreach (string path in new[] { "", "/", "../bad", "x/../bad", "a//b", "a\\b" })
            Program.Throws<ArgumentException>(() => assembler.Write(Stream.Null, [Source(path)]));
        Program.Throws<NotSupportedException>(() => assembler.Write(Stream.Null,
            [Source("café"), Source("cafè")]));
        Program.Throws<ArgumentException>(() => assembler.Write(Stream.Null, [Source("a"), Source("/a")]));
        Program.Throws<ArgumentException>(() => assembler.Write(Stream.Null, [Source("a"), Source("a/b")]));
        Program.Throws<ArgumentOutOfRangeException>(() => assembler.Write(Stream.Null, [Source("a", -1)]));
        Program.Throws<EndOfStreamException>(() => assembler.Write(Stream.Null, [Source("a", 2)]));
        Program.Throws<InvalidDataException>(() => assembler.Write(Stream.Null, [Source("a", 1, [1, 2])]));
        int oversizedOpens = 0;
        var oversized = new ProsperoPs5InnerFileSource
        {
            Path = "/large", Length = 1L << 40,
            OpenRead = () => { oversizedOpens++; return Stream.Null; },
        };
        Program.Throws<NotSupportedException>(() => assembler.Write(Stream.Null, [oversized]));
        Program.Equal(0, oversizedOpens, "unrepresentable file size rejected before source opens");
        int opened = 0;
        var excessive = Enumerable.Range(0, 400).Select(i => new ProsperoPs5InnerFileSource
        {
            Path = "/" + new string('x', 200) + i, Length = 1,
            OpenRead = () => { opened++; return new MemoryStream([1]); },
        }).ToArray();
        var wideDirectory = assembler.Write(Stream.Null, excessive);
        Program.Equal(400, opened, "wide-directory source streams each open once");
        Program.Equal(true, wideDirectory.Nodes.Any(n => n.IsDirectory && n.Size > 0x10000),
            "wide directory spans more than one sector");
        var metadata = new ProsperoPs5InnerMetadata(1, 0);
        byte[] inodeImage = metadata.Build(
            Enumerable.Range(0, 391).Select(i => new ProsperoPs5MetaNode { Size = i }).ToArray(), 1, []);
        Program.Equal(3 * 0x10000, inodeImage.Length, "391 inodes occupy two complete inode sectors");
        Program.Equal(390L, System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(
            inodeImage.AsSpan(2 * 0x10000 + 8)), "inode after first sector boundary preserved");
        var wideTable = new byte[0x10001];
        wideTable[^1] = 0x5a;
        byte[] tableImage = metadata.Build([], 1, [wideTable]);
        Program.Equal(4 * 0x10000, tableImage.Length, "oversized table reserves complete sectors");
        Program.Equal((byte)0x5a, tableImage[3 * 0x10000], "table tail remains intact");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Program.Throws<OperationCanceledException>(() => assembler.Write(Stream.Null, [Source("a")], cancelled.Token));
        using var input = new MemoryStream(new byte[1]);
        Program.Throws<EndOfStreamException>(() => ProsperoPs5InnerImageBuilder.WritePayload(Stream.Null, input, 2));
        // Current highly-compressed geometry is not silently accepted when logical ranges overlap.
        var compressible = new ProsperoPs5InnerFileSource
        {
            Path = "/large-compressible", Length = 8L * 1024 * 1024,
            OpenRead = () => new GeneratedReader(8L * 1024 * 1024),
        };
        var compressedLayout = assembler.Write(Stream.Null, [compressible]);
        Program.Equal(true, compressedLayout.MetaBaseLogical > compressible.Length,
            "highly compressed data does not overlap metadata");
        using var healthy = new MemoryStream(new byte[1]);
        Program.Throws<IOException>(() => ProsperoPs5InnerImageBuilder.WritePayload(new BrokenWriter(), healthy, 1));
    }

    private static void BoundedPayloadAllocation()
    {
        // Warm-up excludes JIT/static initialization. A synthetic input avoids allocating a source image.
        ProsperoPs5InnerImageBuilder.WritePayload(Stream.Null, new GeneratedReader(1), 1, storeRaw: true);
        long before = GC.GetAllocatedBytesForCurrentThread();
        const long size = 32L * 1024 * 1024;
        using var input = new GeneratedReader(size);
        using var output = new ForwardWriter(Stream.Null);
        var result = ProsperoPs5InnerImageBuilder.WritePayload(output, input, size, storeRaw: true);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Program.Equal(size, result.Length, "large synthetic payload length");
        // Total allocations can include one bounded encoded array per block, but no whole-file array.
        Program.Equal(true, allocated < size + 4 * 1024 * 1024, "no extra whole-file allocations");
        Program.Equal(128, result.Blocks.Count, "large payload block metadata");
        Program.Equal(true, output.MaxWrite <= 0x40000, "large payload writes stay block-bounded");
    }

    private sealed class ForwardReader(Stream inner, int maxRead) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, Math.Min(count, maxRead));
        public override int Read(Span<byte> buffer) => inner.Read(buffer[..Math.Min(buffer.Length, maxRead)]);
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class GeneratedReader(long remaining) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (buffer.Length > 0x40000) throw new InvalidOperationException("Unbounded input request");
            int count = (int)Math.Min(buffer.Length, remaining);
            buffer[..count].Fill(0x5a);
            remaining -= count;
            return count;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private class ForwardWriter(Stream inner) : Stream
    {
        public bool Sought;
        public int MaxWrite;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            MaxWrite = Math.Max(MaxWrite, buffer.Length);
            inner.Write(buffer);
        }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) { Sought = true; throw new NotSupportedException(); }
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class BrokenWriter() : ForwardWriter(Stream.Null)
    {
        public override void Write(ReadOnlySpan<byte> buffer) => throw new IOException("injected write failure");
    }
}
