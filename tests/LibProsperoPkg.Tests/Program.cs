namespace LibProsperoPkg.Tests;

internal static class Program
{
    private static int assertions;

    internal static void Equal<T>(T expected, T actual, string context)
    {
        assertions++;
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"{context}: expected {expected}, got {actual}");
    }

    internal static void Throws<T>(Action action) where T : Exception
    {
        assertions++;
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}");
    }

    private static void Main()
    {
#if !STREAMING_NATIVE_TESTS
        // The GP5 parity reference intentionally uses the legacy dynamic XML serializer.
        // It belongs to the managed suite; the native streaming runner links only streaming tests.
        HashTests.Run();
        Gp5Tests.Run();
        AotHelpersTests.Run();
#endif
        StreamingTests.Run();
        NapsStreamingTests.Run();
        OuterStreamingTests.Run();
#if STREAMING_NATIVE_TESTS
        Console.WriteLine($"PASS {assertions} NativeAOT streaming regression assertions.");
#else
        Console.WriteLine($"PASS {assertions} SHA3/GP5/AOT/streaming regression assertions.");
#endif
    }
}
