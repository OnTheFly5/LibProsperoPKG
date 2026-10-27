// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.PFS;
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Integrity metadata for finalized FIH+PFS+CNT bytes, excluding the trailing SI archive.
/// The digests are over final on-disk bytes, not the outer writer's plaintext block digests.
/// </summary>
public sealed class ProsperoFinalizedMountDigests
{
    private readonly OuterDigestTable? blockDigests;
    public long Length { get; }
    public ReadOnlyMemory<byte> MountDigest { get; }
    public ReadOnlyMemory<byte> SuperblockDigest { get; }
    public ReadOnlyMemory<byte> PlayGoChunkCrc { get; }
    public bool HasBlockDigests => blockDigests is not null;

    /// <summary>
    /// Supplies externally calculated metadata (for example from an FTP server). The caller must
    /// ensure every digest/CRC covers the same finalized mount. This validates shape, not provenance.
    /// </summary>
    public ProsperoFinalizedMountDigests(long length, ReadOnlySpan<byte> mountDigest,
        ReadOnlySpan<byte> superblockDigest, ReadOnlySpan<byte> playGoChunkCrc)
    {
        int count = ValidateLength(length);
        if (mountDigest.Length != 32 || superblockDigest.Length != 32)
            throw new ArgumentException("SHA3-256 digests must contain exactly 32 bytes.");
        if (playGoChunkCrc.Length != checked(count * 4))
            throw new ArgumentException("Expected one CRC-32C per 64 KiB block (including a partial tail).", nameof(playGoChunkCrc));
        Length = length;
        MountDigest = mountDigest.ToArray();
        SuperblockDigest = superblockDigest.ToArray();
        PlayGoChunkCrc = playGoChunkCrc.ToArray();
    }

    private ProsperoFinalizedMountDigests(long length, byte[] mountDigest, byte[] rootDigest,
        byte[] crc, OuterDigestTable? blocks)
    {
        Length = length; MountDigest = mountDigest; SuperblockDigest = rootDigest;
        PlayGoChunkCrc = crc; blockDigests = blocks;
    }

    /// <summary>Optional final on-disk block digests, used by the legacy SI identity-map profile.</summary>
    public ReadOnlyMemory<byte> GetBlockDigest(int index)
        => (blockDigests ?? throw new InvalidOperationException("Block digests were not captured.")).Get(index);

    private static int ValidateLength(long length)
    {
        if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
        long count = (length - 1) / ProsperoImageDigests.BlockSize + 1;
        if (count > int.MaxValue / 4)
            throw new NotSupportedException("PlayGo CRC metadata exceeds the supported array size.");
        return (int)count;
    }

    /// <summary>
    /// Hashes exactly <paramref name="length"/> bytes from the source's current cursor, after all
    /// mount patches. Reads at most 64 KiB at a time, never seeks or queries source length/position,
    /// and leaves the source open. Any following SI bytes are left unread. The optional superblock
    /// offset is relative to these mount bytes; it must select a complete aligned 64 KiB block.
    /// No superblock offset yields an all-zero root slot, matching the legacy SI fallback.
    /// </summary>
    public static ProsperoFinalizedMountDigests Compute(Stream source, long length,
        long? superblockOffset = null, bool captureBlockDigests = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead) throw new ArgumentException("Readable source required.", nameof(source));
        int count = ValidateLength(length);
        const int blockSize = ProsperoImageDigests.BlockSize;
        if (superblockOffset is { } offset && (offset < 0 || offset % blockSize != 0 || offset > length - blockSize))
            throw new ArgumentOutOfRangeException(nameof(superblockOffset));
        cancellationToken.ThrowIfCancellationRequested();
        var crc = new byte[checked(count * 4)];
        var buffer = new byte[blockSize];
        var root = new byte[32];
        var blocks = captureBlockDigests ? new OuterDigestTable() : null;
        using var whole = new Sha3Digest();
        long consumed = 0;
        for (int i = 0; i < count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int n = (int)Math.Min(blockSize, length - consumed);
            int read = 0;
            while (read < n)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int got = source.Read(buffer, read, n - read);
                if (got == 0) throw new EndOfStreamException("Finalized mount ended before the specified length.");
                read += got;
            }
            var bytes = buffer.AsSpan(0, n);
            whole.AppendData(bytes);
            BinaryPrimitives.WriteUInt32LittleEndian(crc.AsSpan(i * 4), ProsperoCrc32C.Compute(bytes));
            if (blocks is not null || superblockOffset == consumed)
            {
                byte[] digest = Sha3Digest.HashData(bytes);
                blocks?.Set(i, digest);
                if (superblockOffset == consumed) root = digest;
            }
            consumed += n;
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new ProsperoFinalizedMountDigests(length, whole.GetHashAndReset(), root, crc, blocks);
    }
}
