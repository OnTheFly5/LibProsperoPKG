using System.Text;
using System.Xml;
using System.Xml.Serialization;
using LibProsperoPkg.GP5;

namespace LibProsperoPkg.Tests;

internal static class Gp5Tests
{
    private static readonly XmlSerializer LegacySerializer = new(typeof(Gp5Project));

    private static byte[] LegacyWrite(Gp5Project project)
    {
        using var output = new MemoryStream();
        using (var writer = XmlWriter.Create(output, new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            Encoding = new UTF8Encoding(false),
            OmitXmlDeclaration = false,
        }))
            LegacySerializer.Serialize(writer, project, new XmlSerializerNamespaces([XmlQualifiedName.Empty]));
        return output.ToArray();
    }

    private static void Compare(Gp5Project project)
    {
        byte[] expected = LegacyWrite(project);
        using var output = new MemoryStream();
        Gp5Project.WriteTo(project, output);
        Program.Equal(true, output.CanWrite, "writer leaves stream open");
        Program.Equal(Encoding.UTF8.GetString(expected), Encoding.UTF8.GetString(output.ToArray()), "legacy XML bytes");
        output.Position = 0;
        var read = Gp5Project.ReadFrom(output);
        Program.Equal(true, output.CanRead, "reader leaves stream open");
        using var legacyInput = new MemoryStream(expected);
        var legacyRead = (Gp5Project)LegacySerializer.Deserialize(legacyInput)!;
        Program.Equal(Encoding.UTF8.GetString(LegacyWrite(legacyRead)), Encoding.UTF8.GetString(LegacyWrite(read)), "XML round-trip");
    }

    internal static void Run()
    {
        foreach (var type in Enum.GetValues<Gp5VolumeType>())
        {
            Compare(Gp5Project.Create(type));
            var project = Gp5Project.Create(type);
            project.Format = "gp5";
            project.Version = 1234;
            project.Volume.VolumeId = "Olá & <teste>";
            project.Volume.VolumeTimestamp = "";
            project.Volume.Package.ContentId = "CONTENT";
            project.Volume.Package.StorageType = "digital";
            project.Volume.Package.AppPath = "c:\\my \"app\"";
            project.GlobalExclude = "A&B";
            project.RootDir.SourcePath = "/tmp/Olá & \"<>\"";
            project.RootDir.DirExclude = "";
            project.RootDir.FileExclude = "*.dds;*.gp5";
            Compare(project);
            project.Files.Add(new Gp5File { SourcePath = "/a&b", DestinationPath = "sce_sys\\param.json" });
            project.Folders.Add(new Gp5Dir { SourcePath = "/c", DestinationPath = "data" });
            Compare(project);
            project.Files.Clear();
            Compare(project); // folders-only flat layout
        }
        var scenarios = Gp5Project.Create(Gp5VolumeType.prospero_app);
        scenarios.Volume.ChunkInfo!.Chunks.Add(new Gp5Chunk { Id = 1, Label = "Á & B" });
        scenarios.Volume.ChunkInfo.ChunkCount = 2;
        scenarios.Volume.ChunkInfo.Scenarios.Items.Add(new Gp5Scenario { Id = 1, Type = "full", Label = "<All>", InitialChunkCount = 2, Chunks = "0 1" });
        scenarios.Volume.ChunkInfo.ScenarioCount = 2;
        Compare(scenarios);
        scenarios.Volume.ChunkInfo.Scenarios.Items[0].Chunks = "";
        Compare(scenarios);
        scenarios.Volume.ChunkInfo.Scenarios.Items[0].Chunks = null!;
        scenarios.Volume.Package.Passcode = null!;
        scenarios.Volume.VolumeTypeName = null!;
        Compare(scenarios);
        scenarios.Volume.ChunkInfo.Chunks.Clear();
        scenarios.Volume.ChunkInfo.Scenarios.Items.Clear();
        Compare(scenarios);

        foreach (string xml in new[]
        {
            "<psproject />",
            "<psproject><volume><volume_type>unknown-type</volume_type><package /></volume><unknown /></psproject>",
            "<psproject version='-1'><volume><chunk_info><chunks><chunk /></chunks><scenarios><scenario>0 2</scenario></scenarios></chunk_info></volume><files><file /></files></psproject>",
            "<psproject><volume><chunk_info><scenarios><scenario /></scenarios></chunk_info></volume></psproject>",
        })
        {
            using var oldInput = new MemoryStream(Encoding.UTF8.GetBytes(xml));
            var old = (Gp5Project)LegacySerializer.Deserialize(oldInput)!;
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(xml));
            var actual = Gp5Project.ReadFrom(input);
            Program.Equal(Encoding.UTF8.GetString(LegacyWrite(old)), Encoding.UTF8.GetString(LegacyWrite(actual)), "legacy read defaults");
        }
        Program.Throws<InvalidOperationException>(() => Gp5Project.ReadFrom(new MemoryStream("<wrong/>"u8.ToArray())));
        Program.Throws<XmlException>(() => Gp5Project.ReadFrom(new MemoryStream("<!DOCTYPE psproject [<!ENTITY e 'text'>]><psproject>&e;</psproject>"u8.ToArray())));
        Program.Throws<XmlException>(() => Gp5Project.ReadFrom(new MemoryStream("<psproject>"u8.ToArray())));
    }
}
