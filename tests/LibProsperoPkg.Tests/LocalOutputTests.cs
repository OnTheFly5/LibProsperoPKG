using LibProsperoPkg.PKG;

namespace LibProsperoPkg.Tests;

internal static class LocalOutputTests
{
    internal static void Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-output-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            SuccessfulOutput(root);
            ExistingOutputs(root);
            FailureAndCancellation(root);
            PublicationRace(root);
            ReplacedPartial(root);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void SuccessfulOutput(string root)
    {
        string final = Path.Combine(root, "success.pkg");
        FileStream? borrowed = null;
        int result = ProsperoLocalPackageOutput.Write(final, (stream, token) =>
        {
            borrowed = stream;
            Program.Equal(false, File.Exists(final), "final absent during generation");
            Program.Equal(true, File.Exists(final + ".part"), "partial visible during generation");
            stream.Write(new byte[] { 0, 2, 3 });
            stream.Position = 0;
            stream.WriteByte(1);
            stream.Position = 0;
            Program.Equal(1, stream.ReadByte(), "selected partial can be patched/read");
            return 42;
        });
        Program.Equal(42, result, "generation result returned only after publish");
        Program.Equal(true, File.ReadAllBytes(final).AsSpan().SequenceEqual(new byte[] { 1, 2, 3 }), "published bytes");
        Program.Equal(false, File.Exists(final + ".part"), "partial renamed");
        Program.Equal(false, borrowed!.CanWrite, "borrowed stream closes after callback");
        Program.Throws<DirectoryNotFoundException>(() => ProsperoLocalPackageOutput.Write(Path.Combine(root, "missing", "file.pkg"), (stream, token) => 1));
        Program.Equal(false, Directory.Exists(Path.Combine(root, "missing")), "output directory not implicitly created");
    }

    private static void ExistingOutputs(string root)
    {
        string final = Path.Combine(root, "exists.pkg");
        File.WriteAllText(final, "final");
        File.WriteAllText(final + ".part", "partial");
        int calls = 0;
        Program.Throws<IOException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) => { calls++; return 1; }, path => { calls++; return true; }));
        Program.Equal(0, calls, "existing final fails before prompts/generation");
        Program.Equal("final", File.ReadAllText(final), "existing final preserved");
        Program.Equal("partial", File.ReadAllText(final + ".part"), "existing partial preserved when final exists");
        File.Delete(final);
        Program.Throws<IOException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) => { calls++; return 1; }));
        Program.Throws<IOException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) => { calls++; return 1; }, path => false));
        Program.Equal("partial", File.ReadAllText(final + ".part"), "declined partial preserved");
        Program.Equal(0, calls, "declining never starts generation");
        ProsperoLocalPackageOutput.Write(final, (stream, token) =>
        {
            Program.Equal(0L, stream.Length, "approved retry starts from an empty new file");
            stream.WriteByte(7);
            return true;
        }, path => { Program.Equal(final + ".part", path, "confirmation identifies exact partial"); return true; });
        Program.Equal(1L, new FileInfo(final).Length, "old partial never resumed");
    }

    private static void FailureAndCancellation(string root)
    {
        string final = Path.Combine(root, "failed.pkg");
        Program.Throws<InvalidDataException>(() => ProsperoLocalPackageOutput.Write<int>(final, (stream, token) =>
        {
            stream.WriteByte(1);
            throw new InvalidDataException("failed generator");
        }));
        Program.Equal(false, File.Exists(final), "failed output never published");
        Program.Equal(false, File.Exists(final + ".part"), "failed partial cleaned");
        using var cts = new CancellationTokenSource();
        Program.Throws<OperationCanceledException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) =>
        {
            stream.WriteByte(1);
            cts.Cancel();
            return true;
        }, cancellationToken: cts.Token));
        Program.Equal(false, File.Exists(final + ".part"), "cancelled partial cleaned");
        Program.Throws<ObjectDisposedException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) =>
        {
            stream.Dispose();
            return true;
        }));
        Program.Equal(false, File.Exists(final + ".part"), "closed borrowed stream causes failure and cleanup");
        File.WriteAllText(final + ".part", "existing");
        using var promptCancellation = new CancellationTokenSource();
        Program.Throws<OperationCanceledException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) => true,
            path => { promptCancellation.Cancel(); return true; }, promptCancellation.Token));
        Program.Equal("existing", File.ReadAllText(final + ".part"), "cancellation during consent preserves old partial");
    }

    private static void PublicationRace(string root)
    {
        string final = Path.Combine(root, "race.pkg");
        Program.Throws<IOException>(() => ProsperoLocalPackageOutput.Write(final, (stream, token) =>
        {
            stream.WriteByte(1);
            File.WriteAllText(final, "external final");
            return true;
        }));
        Program.Equal("external final", File.ReadAllText(final), "final created during generation never overwritten");
        Program.Equal(false, File.Exists(final + ".part"), "owned partial removed on publish conflict");
    }

    private static void ReplacedPartial(string root)
    {
        if (!OperatingSystem.IsWindows()) // Windows denies unlink while the generation stream is open.
        {
            string final = Path.Combine(root, "replacement.pkg");
            AggregateException? failure = null;
            try
            {
                ProsperoLocalPackageOutput.Write<int>(final, (stream, token) =>
                {
                    stream.WriteByte(1);
                    File.Delete(final + ".part");
                    File.WriteAllText(final + ".part", "replacement");
                    throw new InvalidDataException("generator failed after external replacement");
                });
            }
            catch (AggregateException error) { failure = error; }
            Program.Equal(true, failure is not null, "cleanup failure is reported with primary failure");
            Program.Equal(true, failure!.InnerExceptions[0] is InvalidDataException, "original failure retained");
            Program.Equal(true, failure.InnerExceptions[1] is IOException, "cleanup identity failure retained");
            Program.Equal("replacement", File.ReadAllText(final + ".part"), "cleanup preserves replaced partial");
            Program.Equal(false, File.Exists(final), "replacement never published after generation failure");
            string returned = Path.Combine(root, "replacement-success.pkg");
            Program.Throws<AggregateException>(() => ProsperoLocalPackageOutput.Write(returned, (stream, token) =>
            {
                File.Delete(returned + ".part");
                File.WriteAllText(returned + ".part", "foreign output");
                return true;
            }));
            Program.Equal("foreign output", File.ReadAllText(returned + ".part"), "successful callback cannot publish replacement");
            Program.Equal(false, File.Exists(returned), "identity mismatch aborts publication");
        }
        string prompt = Path.Combine(root, "prompt-race.pkg");
        File.WriteAllText(prompt + ".part", "original");
        Program.Throws<IOException>(() => ProsperoLocalPackageOutput.Write(prompt, (stream, token) => true, path =>
        {
            File.Move(path, path + ".old");
            File.WriteAllText(path, "new external partial");
            return true;
        }));
        Program.Equal("new external partial", File.ReadAllText(prompt + ".part"), "consent applies only to identified original partial");
    }
}
