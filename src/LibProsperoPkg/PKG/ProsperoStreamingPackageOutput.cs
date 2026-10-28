// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using System;
using System.IO;
using System.Threading;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Transport-neutral operations for one exclusively owned, initially empty package destination.
/// Calls are synchronous and ordered. Implementations must consume borrowed buffers before returning,
/// apply backpressure, and throw on incomplete operations. Generation does not dispose this output.
/// No payload read, arbitrary seek, creation, deletion or publication operation is requested here.
/// </summary>
public interface IProsperoStreamingPackageOutput
{
    /// <summary>Append all bytes, in calls of at most 64 KiB, or throw. Never retain the span.</summary>
    void Append(ReadOnlySpan<byte> bytes);
    /// <summary>Complete all preceding appends/patches before returning.</summary>
    void Flush();
    /// <summary>Replace an existing range without truncation, in calls of at most 1024 bytes.</summary>
    void Patch(long offset, ReadOnlySpan<byte> bytes);
    /// <summary>
    /// After all mount appends and patches have completed, calculate/return integrity over exactly
    /// length finalized bytes. The supplied superblock offset selects an aligned 64 KiB block.
    /// All SHA3 digests and per-64-KiB CRC-32C records must cover the same stable bytes, excluding SI.
    /// An FTP sink can combine server-side SHA3 with locally captured/recomputed CRC metadata.
    /// Do not download or retain the whole mount merely to implement this operation. On return the
    /// destination must remain ready to append SI at length. No publication is performed by the writer.
    /// </summary>
    ProsperoFinalizedMountDigests FinalizeMount(long length, long superblockOffset,
        CancellationToken cancellationToken);
}

internal sealed class LocalStreamingPackageOutput(FileStream file) : IProsperoStreamingPackageOutput
{
    public void Append(ReadOnlySpan<byte> bytes) => file.Write(bytes);
    public void Flush() => file.Flush();
    public void Patch(long offset, ReadOnlySpan<byte> bytes)
    {
        if (offset < 0 || offset > file.Length - bytes.Length)
            throw new ArgumentOutOfRangeException(nameof(offset));
        long cursor = file.Position;
        try { file.Position = offset; file.Write(bytes); }
        finally { file.Position = cursor; }
    }
    public ProsperoFinalizedMountDigests FinalizeMount(long length, long superblockOffset,
        CancellationToken cancellationToken)
    {
        if (file.Position != length || file.Length != length)
            throw new InvalidDataException("Unexpected mount output extent.");
        file.Flush();
        file.Position = 0;
        return ProsperoFinalizedMountDigests.Compute(file, length, superblockOffset,
            cancellationToken: cancellationToken);
    }
}

internal sealed class StreamingPackageAppendStream(IProsperoStreamingPackageOutput output,
    CancellationToken token) : Stream
{
    private long position;
    public override void Write(ReadOnlySpan<byte> bytes)
    {
        while (!bytes.IsEmpty)
        {
            token.ThrowIfCancellationRequested();
            int count = Math.Min(65536, bytes.Length);
            long next = checked(position + count);
            output.Append(bytes[..count]);
            position = next;
            bytes = bytes[count..];
        }
    }
    public override void Write(byte[] bytes, int offset, int count) => Write(bytes.AsSpan(offset, count));
    public override void Flush() { token.ThrowIfCancellationRequested(); output.Flush(); }
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Position { get => position; set => throw new NotSupportedException(); }
    public override long Length => throw new NotSupportedException();
    public override int Read(byte[] bytes, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long length) => throw new NotSupportedException();
}
