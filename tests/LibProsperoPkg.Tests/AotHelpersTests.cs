using System.Runtime.InteropServices;
using LibProsperoPkg.Metadata;
using LibProsperoPkg.Util;

namespace LibProsperoPkg.Tests;

internal static class AotHelpersTests
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Record
    {
        public int First;
        public int Second;
    }

    internal static void Run()
    {
        var param = new ProsperoParam();
        var intent = Enum.GetValues<ProsperoIntentType>()[0];
        param.AddPermittedIntent(intent);
        Program.Equal(1, param.PermittedIntentTokens.Count, "append intent");
        param.SetPermittedIntents(intent, intent);
        Program.Equal(2, ProsperoParam.Parse(param.ToJson()).PermittedIntentTokens.Count, "intent JSON nodes");
        param.SetServiceIdForSharing(["Olá", "123"]);
        Program.Equal("Olá", ProsperoParam.Parse(param.ToJson()).ServiceIdForSharing[0], "sharing JSON nodes");
        var manifest = new ProsperoManifest();
        manifest.SetEnableAccessibility(["reader", "zoom"]);
        Program.Equal("zoom", ProsperoManifest.Parse(manifest.ToJson()).EnableAccessibility[1], "accessibility JSON nodes");
        using var input = new MemoryStream(new byte[] { 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0 });
        using var reader = new LibProsperoPkg.Util.StreamReader(input);
        reader.Read(0, out Record record);
        Program.Equal(1, record.First, "generic marshal first");
        Program.Equal(2, record.Second, "generic marshal second");
        Record[] records = new Record[2];
        reader.ReadArray(0, records, 0, records.Length);
        Program.Equal(3, records[1].First, "generic marshal array first");
        Program.Equal(4, records[1].Second, "generic marshal array second");
    }
}
