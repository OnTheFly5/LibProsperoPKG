// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Threading;

namespace LibProsperoPkg.PFS;

/// <summary>An outer file whose size need not be known before writing begins.</summary>
public sealed class ProsperoOuterFileProducer
{
    public required string Name { get; init; }
    public bool Signed { get; init; }

    /// <summary>
    /// Writes the file exactly once to a forward-only stream. Return its logical size for the
    /// inode SizeCompressed field, or null to use the number of bytes written. The callback must
    /// finish synchronously and must not retain the stream. It does not own the destination.
    /// </summary>
    public required Func<Stream, long?> WritePayload { get; init; }
}

/// <summary>Metadata retained after writing an encrypted outer image; contains no file payload.</summary>
public sealed class ProsperoOuterPfsStreamResult
{
    private readonly OuterDigestTable digests;
    internal ProsperoOuterPfsStreamResult(OuterDigestTable digests) => this.digests = digests;
    public int BlockCount => digests.Count;
    public long PfsSize => (long)BlockCount * ProsperoOuterPfsBuilder.BlockSize;
    public required int SuperblockIndex { get; init; }
    public required byte[] SuperblockIcv { get; init; }
    public required IReadOnlyList<int> FileFirstBlock { get; init; }
    public required IReadOnlyList<int> FileBlockCount { get; init; }
    public required IReadOnlyList<long> FileSize { get; init; }
    public required IReadOnlyList<long> FileSizeCompressed { get; init; }

    /// <summary>SHA3-256 of the padded plaintext block, before AES-XTS encryption.</summary>
    public ReadOnlyMemory<byte> GetBlockDigest(int blockIndex) => digests.Get(blockIndex);
}

// Fixed-size pages avoid per-digest objects and a doubling allocation of a contiguous digest array.
internal sealed class OuterDigestTable
{
    private const int EntriesPerPage = 4096;
    private readonly List<byte[]> pages = new();
    internal int Count { get; private set; }
    internal ReadOnlyMemory<byte> Get(int index)
    {
        if ((uint)index >= (uint)Count) throw new ArgumentOutOfRangeException(nameof(index));
        return pages[index / EntriesPerPage].AsMemory(index % EntriesPerPage * 32, 32);
    }
    internal void Set(int index, ReadOnlySpan<byte> digest)
    {
        if (index < 0 || digest.Length != 32) throw new ArgumentOutOfRangeException(nameof(index));
        while (pages.Count <= index / EntriesPerPage) pages.Add(new byte[EntriesPerPage * 32]);
        digest.CopyTo(pages[index / EntriesPerPage].AsSpan(index % EntriesPerPage * 32, 32));
        Count = Math.Max(Count, checked(index + 1));
    }
}

public static partial class ProsperoOuterPfsBuilder
{
    private const int SignedPointerCapacity = BlockSize / 36; // 1820
    private const int OuterDirectSlots = 12;

    /// <summary>
    /// Maximum file size addressed by the implemented direct, single and double-indirect topology.
    /// Triple-indirect addressing has not been validated and is rejected rather than guessed.
    /// </summary>
    public const long MaximumStreamedFileSize =
        (OuterDirectSlots + (long)SignedPointerCapacity + (long)SignedPointerCapacity * SignedPointerCapacity) * BlockSize;

    /// <summary>Number of signed pointer blocks needed for a file, without reading its payload.</summary>
    public static int GetStreamedIndirectBlockCount(long fileSize)
    {
        if (fileSize < 0 || fileSize > MaximumStreamedFileSize)
            throw new ArgumentOutOfRangeException(nameof(fileSize), "File exceeds the supported double-indirect layout.");
        long blocks = Math.Max(1, (fileSize + BlockSize - 1) / BlockSize);
        long extra = blocks - OuterDirectSlots;
        if (extra <= 0) return 0;
        if (extra <= SignedPointerCapacity) return 1;
        return checked(2 + (int)((extra - SignedPointerCapacity + SignedPointerCapacity - 1) / SignedPointerCapacity));
    }

    /// <summary>
    /// Writes a data-first, signed and encrypted outer PFS to an append-only destination. Only
    /// digest pages and structural metadata are retained; payloads pass through a 64 KiB buffer.
    /// Sizes are discovered while producers run, so the inner image can be generated in that callback.
    /// The destination is left open. On failure the caller must discard its incomplete output.
    /// Image-tree XML and package-wide digest/finalization are separate operations.
    /// </summary>
    public static ProsperoOuterPfsStreamResult WriteForPackage(
        Stream destination, IReadOnlyList<ProsperoOuterFileProducer> files,
        ProsperoOuterPfsBuildParameters parameters, byte[] ekpfs,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(parameters);
        if (!destination.CanWrite) throw new ArgumentException("A writable destination is required.", nameof(destination));
        // The nwonly profile has very few outer files. Retain its single-sector inode table.
        if (files.Count == 0 || files.Count > BlockSize / ProsperoDinodeS32.SizeOf - MetadataInodeCount)
            throw new ArgumentOutOfRangeException(nameof(files), "Outer inodes must fit one metadata block.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var descriptors = new ProsperoOuterFile[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            var file = files[i] ?? throw new ArgumentException("Null producer.", nameof(files));
            ArgumentNullException.ThrowIfNull(file.WritePayload);
            string name = file.Name;
            if (string.IsNullOrEmpty(name) || name.Length > 255 || name == "." || name == ".." ||
                name.IndexOfAny(new[] { '/', '\\', '\0' }) >= 0 || !names.Add(name))
                throw new ArgumentException("Outer names must be unique, plain ASCII file names (up to 255 bytes).", nameof(files));
            foreach (char c in name)
                if (c > 0x7f) throw new ArgumentException("Outer names must be ASCII.", nameof(files));
            descriptors[i] = new ProsperoOuterFile { Name = name, Data = Array.Empty<byte>() };
        }
        byte[] seed = (parameters.Seed ?? new byte[16]).AsSpan().ToArray();
        var (tweak, data) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
        var snapshot = new ProsperoOuterPfsBuildParameters
        {
            Seed = seed, TimestampSeconds = parameters.TimestampSeconds,
            TimestampNanoseconds = parameters.TimestampNanoseconds,
        };
        cancellationToken.ThrowIfCancellationRequested();
        using var xts = new XtsBlockTransform(data, tweak);
        var digests = new OuterDigestTable();
        int nextBlock = 0;
        void Emit(byte[] block, ProsperoOuterBlockKind kind)
        {
            cancellationToken.ThrowIfCancellationRequested();
            digests.Set(nextBlock, ProsperoOuterPfsSignature.ComputeBlockHash(block));
            if (kind != ProsperoOuterBlockKind.Plaintext)
                xts.CryptSector(block, ProsperoOuterPfsSignature.BlockSector(nextBlock, kind == ProsperoOuterBlockKind.Signed), true);
            destination.Write(block);
            nextBlock = checked(nextBlock + 1);
        }
        int count = files.Count;
        var first = new int[count];
        var blocks = new int[count];
        var sizes = new long[count];
        var logicalSizes = new long[count];
        for (int i = 0; i < count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            first[i] = nextBlock;
            var kind = files[i].Signed ? ProsperoOuterBlockKind.Signed : ProsperoOuterBlockKind.Data;
            using var sink = new OuterFileSink(b => Emit(b, kind), cancellationToken);
            long? logicalSize;
            try { logicalSize = files[i].WritePayload(sink); }
            finally { sink.CloseProducer(); }
            if (logicalSize < 0) throw new InvalidDataException("A logical file size cannot be negative.");
            sizes[i] = sink.BytesWritten;
            logicalSizes[i] = logicalSize ?? sizes[i];
            sink.Finish();
            blocks[i] = nextBlock - first[i];
        }
        int superblockIndex = nextBlock;
        int inodeIndex = checked(superblockIndex + 1);
        int rootIndex = checked(superblockIndex + 2);
        int fltIndex = checked(superblockIndex + 3);
        int metadataNext = checked(superblockIndex + 4);
        var nodes = new List<OuterPointerNode>();
        var single = new OuterPointerNode?[count];
        var doubleRoot = new OuterPointerNode?[count];
        for (int i = 0; i < count; i++)
        {
            int extra = blocks[i] - OuterDirectSlots;
            if (extra <= 0) continue;
            single[i] = new OuterPointerNode(metadataNext++, first[i] + OuterDirectSlots,
                Math.Min(extra, SignedPointerCapacity));
            nodes.Add(single[i]!);
            extra -= SignedPointerCapacity;
            if (extra <= 0) continue;
            var root = new OuterPointerNode(metadataNext++, 0, 0);
            doubleRoot[i] = root;
            nodes.Add(root);
            int cursor = first[i] + OuterDirectSlots + SignedPointerCapacity;
            while (extra > 0)
            {
                int n = Math.Min(extra, SignedPointerCapacity);
                var leaf = new OuterPointerNode(metadataNext++, cursor, n);
                root.Children.Add(leaf);
                nodes.Add(leaf);
                cursor += n;
                extra -= n;
            }
        }
        int urootIndex = metadataNext;
        int totalBlocks = checked(urootIndex + 1);
        var pointerBuffer = new byte[BlockSize];
        // Parents precede children physically, but their hashes are calculated bottom-up.
        for (int i = nodes.Count - 1; i >= 0; i--)
        {
            FillPointerBlock(pointerBuffer, nodes[i], digests);
            digests.Set(nodes[i].Index, ProsperoOuterPfsSignature.ComputeBlockHash(pointerBuffer));
        }
        var rootBlock = new byte[BlockSize];
        var fltBlock = new byte[BlockSize];
        var urootBlock = new byte[BlockSize];
        BuildSuperRootDirents(rootBlock);
        BuildFlatPathTable(fltBlock, descriptors);
        BuildUrootDirents(urootBlock, descriptors);
        digests.Set(rootIndex, ProsperoOuterPfsSignature.ComputeBlockHash(rootBlock));
        digests.Set(fltIndex, ProsperoOuterPfsSignature.ComputeBlockHash(fltBlock));
        digests.Set(urootIndex, ProsperoOuterPfsSignature.ComputeBlockHash(urootBlock));
        ProsperoDinodeS32 Inode(ushort mode, ushort links, uint flags, long size, long logical, int start, int n)
        {
            var inode = new ProsperoDinodeS32
            {
                Mode = (ProsperoInodeMode)mode, Nlink = links, Flags = (ProsperoInodeFlags)flags,
                Size = size, SizeCompressed = logical, Blocks = (uint)n,
            };
            StampTime(inode, snapshot);
            for (int j = 0; j < Math.Min(n, OuterDirectSlots); j++)
                inode.db[j] = new ProsperoBlockSig { block = start + j, sig = digests.Get(start + j).ToArray() };
            return inode;
        }
        using var inodeStream = new MemoryStream(BlockSize);
        Inode(ModeDir, 1, FlagsInternalMeta, BlockSize, BlockSize, rootIndex, 1).WriteToStream(inodeStream);
        long fltSize = FltDataOffset + count * 16L;
        Inode(ModeFile, 1, FlagsInternalMeta, fltSize, fltSize, fltIndex, 1).WriteToStream(inodeStream);
        Inode(ModeDir, 3, FlagsDir, BlockSize, BlockSize, urootIndex, 1).WriteToStream(inodeStream);
        for (int i = 0; i < count; i++)
        {
            var inode = Inode(ModeFile, 1, FlagsFile, sizes[i], logicalSizes[i], first[i], blocks[i]);
            if (single[i] is { } s) inode.ib[0] = new ProsperoBlockSig { block = s.Index, sig = digests.Get(s.Index).ToArray() };
            if (doubleRoot[i] is { } d) inode.ib[1] = new ProsperoBlockSig { block = d.Index, sig = digests.Get(d.Index).ToArray() };
            inode.WriteToStream(inodeStream);
        }
        var inodeBlock = new byte[BlockSize];
        CopyStream(inodeStream, inodeBlock);
        var superblock = new byte[BlockSize];
        BuildSuperblock(superblock, snapshot, count, totalBlocks, inodeIndex,
            ProsperoOuterPfsSignature.ComputeBlockHash(inodeBlock));
        byte[] icv = ProsperoOuterPfsSignature.ComputeSuperblockIcv(superblock);
        Emit(superblock, ProsperoOuterBlockKind.Plaintext);
        Emit(inodeBlock, ProsperoOuterBlockKind.Signed);
        Emit(rootBlock, ProsperoOuterBlockKind.Signed);
        Emit(fltBlock, ProsperoOuterBlockKind.Signed);
        foreach (var node in nodes)
        {
            FillPointerBlock(pointerBuffer, node, digests);
            Emit(pointerBuffer, ProsperoOuterBlockKind.Signed);
        }
        Emit(urootBlock, ProsperoOuterBlockKind.Signed);
        return new ProsperoOuterPfsStreamResult(digests)
        {
            SuperblockIndex = superblockIndex, SuperblockIcv = icv,
            FileFirstBlock = Array.AsReadOnly(first), FileBlockCount = Array.AsReadOnly(blocks),
            FileSize = Array.AsReadOnly(sizes), FileSizeCompressed = Array.AsReadOnly(logicalSizes),
        };
    }

    private sealed class OuterPointerNode(int index, int firstData, int count)
    {
        internal int Index { get; } = index;
        internal int FirstData { get; } = firstData;
        internal int Count { get; } = count;
        internal List<OuterPointerNode> Children { get; } = new();
    }

    private static void FillPointerBlock(byte[] buffer, OuterPointerNode node, OuterDigestTable digests)
    {
        Array.Clear(buffer);
        int count = node.Children.Count == 0 ? node.Count : node.Children.Count;
        for (int i = 0; i < count; i++)
        {
            int index = node.Children.Count == 0 ? node.FirstData + i : node.Children[i].Index;
            digests.Get(index).Span.CopyTo(buffer.AsSpan(i * 36, 32));
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(i * 36 + 32), index);
        }
    }

    private sealed class OuterFileSink(Action<byte[]> emit, CancellationToken cancellationToken) : Stream
    {
        private readonly byte[] buffer = new byte[BlockSize];
        private int used;
        private bool closed;
        private ExceptionDispatchInfo? failure;
        internal long BytesWritten { get; private set; }
        internal void CloseProducer() => closed = true;
        internal void Finish()
        {
            failure?.Throw();
            cancellationToken.ThrowIfCancellationRequested();
            if (used != 0 || BytesWritten == 0)
            {
                buffer.AsSpan(used).Clear();
                emit(buffer);
                used = 0;
            }
        }
        public override void Write(ReadOnlySpan<byte> source)
        {
            failure?.Throw();
            try
            {
                ObjectDisposedException.ThrowIf(closed, this);
                cancellationToken.ThrowIfCancellationRequested();
                if (source.Length > MaximumStreamedFileSize - BytesWritten)
                    throw new NotSupportedException("Outer file exceeds the supported double-indirect layout.");
                while (!source.IsEmpty)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int n = Math.Min(buffer.Length - used, source.Length);
                    source[..n].CopyTo(buffer.AsSpan(used));
                    source = source[n..];
                    used += n;
                    BytesWritten += n;
                    if (used == buffer.Length) { emit(buffer); used = 0; }
                }
            }
            catch (Exception error)
            {
                // A producer may catch a callback failure. Never retry an encrypted/partially
                // emitted block, and never allow that producer to turn failed output into success.
                failure = ExceptionDispatchInfo.Capture(error);
                throw;
            }
        }

        public override void Write(byte[] source, int offset, int count) => Write(source.AsSpan(offset, count));
        public override void Flush() { ObjectDisposedException.ThrowIf(closed, this); }
        protected override void Dispose(bool disposing) { closed = true; base.Dispose(disposing); }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !closed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
