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
        HashTests.Run();
        Gp5Tests.Run();
        AotHelpersTests.Run();
        StreamingTests.Run();
        Console.WriteLine($"PASS {assertions} SHA3/GP5/AOT/streaming regression assertions.");
    }
}
