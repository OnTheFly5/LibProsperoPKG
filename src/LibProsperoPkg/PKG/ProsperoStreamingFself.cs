// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.Content;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace LibProsperoPkg.PKG;

// A fake SELF is a small header followed by zero digest areas and selected ELF
// segments. Reopen the source for each segment: catalogs only promise forward
// readers, and program headers may describe overlapping or out-of-order ranges.
internal sealed class ProsperoStreamingFself
{
    private const int ElfHeaderSize = 0x40, PhdrSize = 0x38, ChunkSize = 64 * 1024;
    private readonly ProsperoSourceFile source;
    private readonly byte[] normalizedHeader;
    private readonly byte[] prefix;
    private readonly Segment[] segments;
    internal long Length { get; }
    private readonly record struct Segment(int Index, long SourceOffset, long Size, long OutputOffset);

    private ProsperoStreamingFself(ProsperoSourceFile source, byte[] normalizedHeader, byte[] prefix, Segment[] segments, long length)
    { this.source = source; this.normalizedHeader = normalizedHeader; this.prefix = prefix; this.segments = segments; Length = length; }

    internal static ProsperoStreamingFself Create(ProsperoSourceFile source, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var stream = source.OpenRead();
        if (source.Length < ElfHeaderSize) throw new InvalidDataException("ELF header is truncated: " + source.Path);
        byte[] first = new byte[ElfHeaderSize];
        stream.ReadExactly(first);
        if (!ProsperoFself.IsElf(first)) throw new InvalidDataException("Invalid ELF: " + source.Path);
        var elf = ProsperoElfHeader.Read(first);
        if (elf.ProgramHeaderOffset != ElfHeaderSize || elf.ProgramHeaderEntrySize != PhdrSize)
            throw new InvalidDataException("ELF program headers must directly follow the ELF header: " + source.Path);
        int phlen = checked(elf.ProgramHeaderCount * PhdrSize);
        if (ElfHeaderSize + phlen > ushort.MaxValue || ElfHeaderSize + (long)phlen > source.Length)
            throw new InvalidDataException("ELF program header table is too large or truncated: " + source.Path);
        byte[] phdr = new byte[phlen];
        stream.ReadExactly(phdr);
        ProsperoElfHeader.NormalizeForModule(first);
        var selected = new List<(int Index, long Offset, long Size)>();
        for (int i = 0; i < elf.ProgramHeaderCount; i++)
        {
            var ph = phdr.AsSpan(i * PhdrSize, PhdrSize);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(ph);
            ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(ph[8..]);
            ulong size = BinaryPrimitives.ReadUInt64LittleEndian(ph[0x20..]);
            if (size == 0 || offset > (ulong)source.Length || size > (ulong)source.Length - offset) continue;
            if (type is 1 or 0x61000000 or 0x61000010 or 0x6FFFFF00)
                selected.Add((i, checked((long)offset), checked((long)size)));
        }
        if (selected.Count == 0) throw new InvalidDataException("ELF has no loadable segment content: " + source.Path);
        int count = checked(selected.Count * 2);
        int afterTable = checked(0x20 + count * 0x20);
        int ext = checked((afterTable + ElfHeaderSize + phlen + 15) & ~15);
        int headerSize = checked(ext + 0x40 + 0x30);
        int metaSize = checked(0x110 + (count + 8) * 0x40);
        if (headerSize > ushort.MaxValue || metaSize > ushort.MaxValue)
            throw new InvalidDataException("ELF has too many segments for a SELF header: " + source.Path);
        long cursor = headerSize + metaSize;
        var segments = new Segment[selected.Count];
        for (int i = 0; i < segments.Length; i++)
        {
            cursor = checked(cursor + 0x20);
            segments[i] = new(selected[i].Index, selected[i].Offset, selected[i].Size, cursor);
            cursor = checked((cursor + selected[i].Size + 15) & ~15L);
        }
        // Hash the normalized header and the rest of the complete original ELF.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(first);
        hash.AppendData(phdr);
        var buffer = new byte[ChunkSize];
        long remaining = source.Length - ElfHeaderSize - phlen;
        while (remaining > 0)
        {
            token.ThrowIfCancellationRequested();
            int n = stream.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
            if (n == 0) throw new EndOfStreamException("ELF became shorter: " + source.Path);
            hash.AppendData(buffer, 0, n); remaining -= n;
        }
        if (stream.ReadByte() != -1) throw new InvalidDataException("ELF became longer: " + source.Path);
        byte[] prefix = new byte[headerSize + metaSize];
        var bytes = prefix.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, ProsperoFself.Magic);
        bytes[5] = 1; bytes[6] = 1; bytes[7] = 0x12;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes[8..], 0x101);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes[0x0c..], (ushort)headerSize);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes[0x0e..], (ushort)metaSize);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[0x10..], (ulong)cursor);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes[0x18..], (ushort)count);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes[0x1a..], 0x22);
        for (int i = 0; i < segments.Length; i++)
        {
            var seg = segments[i];
            Entry(bytes, 0x20 + i * 0x40, ((ulong)(i * 2 + 1) << 20) | 0x10004, seg.OutputOffset - 0x20, 0x20);
            Entry(bytes, 0x40 + i * 0x40, ((ulong)seg.Index << 20) | 0x2804, seg.OutputOffset, seg.Size);
        }
        first.CopyTo(bytes[afterTable..]); phdr.CopyTo(bytes[(afterTable + ElfHeaderSize)..]);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[ext..], ProsperoFself.FakeAuthorityId);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[(ext + 8)..], 1);
        hash.GetHashAndReset().CopyTo(bytes[(ext + 0x20)..]);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[(ext + 0x40)..], 3);
        if (metaSize > 0x3f4) BinaryPrimitives.WriteUInt32LittleEndian(bytes[(headerSize + 0x3f0)..], 0x10000);
        return new(source, first, prefix, segments, cursor);
    }

    private static void Entry(Span<byte> b, int at, ulong flags, long offset, long size)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(b[at..], flags);
        BinaryPrimitives.WriteUInt64LittleEndian(b[(at + 8)..], (ulong)offset);
        BinaryPrimitives.WriteUInt64LittleEndian(b[(at + 16)..], (ulong)size);
        BinaryPrimitives.WriteUInt64LittleEndian(b[(at + 24)..], (ulong)size);
    }

    internal Stream OpenRead(CancellationToken token) { source.Validate(); return new Reader(this, token); }

    private sealed class Reader(ProsperoStreamingFself plan, CancellationToken token) : Stream
    {
        private long position;
        private int index;
        private Stream? source;
        private readonly byte[] discard = new byte[ChunkSize];
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            token.ThrowIfCancellationRequested();
            if (buffer.IsEmpty || position == plan.Length) return 0;
            if (position < plan.prefix.Length)
            {
                int n = (int)Math.Min(buffer.Length, plan.prefix.Length - position);
                plan.prefix.AsSpan((int)position, n).CopyTo(buffer); position += n; return n;
            }
            while (index < plan.segments.Length && position >= plan.segments[index].OutputOffset + plan.segments[index].Size)
            { source?.Dispose(); source = null; index++; }
            if (index == plan.segments.Length || position < plan.segments[index].OutputOffset)
            {
                long end = index == plan.segments.Length ? plan.Length : plan.segments[index].OutputOffset;
                int n = (int)Math.Min(buffer.Length, end - position);
                buffer[..n].Clear(); position += n; return n;
            }
            var seg = plan.segments[index];
            if (source is null)
            {
                source = plan.source.OpenRead();
                long skip = seg.SourceOffset;
                while (skip > 0)
                {
                    token.ThrowIfCancellationRequested();
                    int n = source.Read(discard, 0, (int)Math.Min(skip, discard.Length));
                    if (n == 0) throw new EndOfStreamException("ELF became shorter: " + plan.source.Path);
                    skip -= n;
                }
            }
            long sourceOffset = seg.SourceOffset + position - seg.OutputOffset;
            int read = source.Read(buffer[..(int)Math.Min(Math.Min(buffer.Length, ChunkSize), seg.OutputOffset + seg.Size - position)]);
            if (read == 0) throw new EndOfStreamException("ELF became shorter: " + plan.source.Path);
            if (sourceOffset < ElfHeaderSize)
            {
                int n = (int)Math.Min(read, ElfHeaderSize - sourceOffset);
                plan.normalizedHeader.AsSpan((int)sourceOffset, n).CopyTo(buffer);
            }
            position += read;
            if (position == seg.OutputOffset + seg.Size) plan.source.Validate();
            return read;
        }
        protected override void Dispose(bool disposing) { if (disposing) source?.Dispose(); base.Dispose(disposing); }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
