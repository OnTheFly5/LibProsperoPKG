using System;
using System.IO;
using System.Xml;
using System.Xml.Linq;

namespace LibProsperoPkg.GP5;

/// <summary>Explicit GP5 XML codec, without reflection or runtime code generation.</summary>
internal static class Gp5Xml
{
    internal static void Write(Gp5Project project, Stream stream)
    {
        using var writer = XmlWriter.Create(stream, new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            Encoding = new System.Text.UTF8Encoding(false),
            OmitXmlDeclaration = false,
            CloseOutput = false,
        });
        writer.WriteStartDocument();
        writer.WriteStartElement("psproject");
        Attribute(writer, "fmt", project.Format);
        Attribute(writer, "version", project.Version);
        if (project.Volume is { } volume) WriteVolume(writer, volume);
        if (project.Layout == Gp5Layout.Normal)
        {
            Element(writer, "global_exclude", project.GlobalExclude);
            if (project.RootDir is { } root)
            {
                writer.WriteStartElement("rootdir");
                OptionalAttribute(writer, "dir_exclude", root.DirExclude);
                OptionalAttribute(writer, "file_exclude", root.FileExclude);
                OptionalAttribute(writer, "src_path", root.SourcePath);
                writer.WriteEndElement();
            }
        }
        if (project.Files.Count > 0)
        {
            writer.WriteStartElement("files");
            foreach (var file in project.Files)
            {
                if (file is null) continue;
                writer.WriteStartElement("file");
                Attribute(writer, "dst_path", file.DestinationPath);
                Attribute(writer, "src_path", file.SourcePath);
                writer.WriteEndElement();
            }
            writer.WriteEndElement();
        }
        if (project.Folders.Count > 0)
        {
            writer.WriteStartElement("folders");
            foreach (var folder in project.Folders)
            {
                if (folder is null) continue;
                writer.WriteStartElement("dir");
                Attribute(writer, "dst_path", folder.DestinationPath);
                Attribute(writer, "src_path", folder.SourcePath);
                writer.WriteEndElement();
            }
            writer.WriteEndElement();
        }
        writer.WriteEndElement();
        writer.WriteEndDocument();
    }

    private static void WriteVolume(XmlWriter writer, Gp5Volume volume)
    {
        writer.WriteStartElement("volume");
        Element(writer, "volume_type", volume.VolumeTypeName);
        Element(writer, "volume_id", volume.VolumeId);
        Element(writer, "volume_ts", volume.VolumeTimestamp);
        if (volume.Package is { } package)
        {
            writer.WriteStartElement("package");
            OptionalAttribute(writer, "content_id", package.ContentId);
            Attribute(writer, "passcode", package.Passcode);
            OptionalAttribute(writer, "storage_type", package.StorageType);
            OptionalAttribute(writer, "app_path", package.AppPath);
            writer.WriteEndElement();
        }
        if (volume.ChunkInfo is { } info)
        {
            writer.WriteStartElement("chunk_info");
            Attribute(writer, "chunk_count", info.ChunkCount);
            Attribute(writer, "scenario_count", info.ScenarioCount);
            if (info.Chunks is not null)
            {
                writer.WriteStartElement("chunks");
                foreach (var chunk in info.Chunks)
                {
                    if (chunk is null) continue;
                    writer.WriteStartElement("chunk");
                    Attribute(writer, "id", chunk.Id);
                    Attribute(writer, "label", chunk.Label);
                    writer.WriteEndElement();
                }
                writer.WriteEndElement();
            }
            if (info.Scenarios is { } scenarios)
            {
                writer.WriteStartElement("scenarios");
                Attribute(writer, "default_id", scenarios.DefaultId);
                foreach (var scenario in scenarios.Items)
                {
                    if (scenario is null) continue;
                    writer.WriteStartElement("scenario");
                    Attribute(writer, "id", scenario.Id);
                    Attribute(writer, "type", scenario.Type);
                    Attribute(writer, "initial_chunk_count", scenario.InitialChunkCount);
                    Attribute(writer, "label", scenario.Label);
                    if (scenario.Chunks is not null) writer.WriteString(scenario.Chunks);
                    writer.WriteEndElement();
                }
                writer.WriteEndElement();
            }
            writer.WriteEndElement();
        }
        writer.WriteEndElement();
    }

    internal static Gp5Project Read(Stream stream)
    {
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            CloseInput = false,
        });
        var document = XDocument.Load(reader);
        var root = document.Root;
        if (root is null || root.Name != "psproject")
            throw new InvalidOperationException("Expected a GP5 psproject document without an XML namespace.");
        var project = new Gp5Project();
        project.Format = Text(root, "fmt", project.Format);
        project.Version = Number(root, "version", project.Version);
        if (root.Element("volume") is { } volume) project.Volume = ReadVolume(volume);
        if (root.Element("global_exclude") is { } exclude) project.GlobalExclude = exclude.Value;
        if (root.Element("rootdir") is { } dir)
        {
            project.RootDir = new Gp5RootDir
            {
                SourcePath = (string?)dir.Attribute("src_path"),
                DirExclude = (string?)dir.Attribute("dir_exclude"),
                FileExclude = (string?)dir.Attribute("file_exclude"),
            };
        }
        if (root.Element("files") is { } files)
            foreach (var file in files.Elements("file"))
                project.Files.Add(new Gp5File { SourcePath = Text(file, "src_path", ""), DestinationPath = Text(file, "dst_path", "") });
        if (root.Element("folders") is { } folders)
            foreach (var folder in folders.Elements("dir"))
                project.Folders.Add(new Gp5Dir { SourcePath = Text(folder, "src_path", ""), DestinationPath = Text(folder, "dst_path", "") });
        return project;
    }

    private static Gp5Volume ReadVolume(XElement element)
    {
        var result = new Gp5Volume();
        if (element.Element("volume_type") is { } type) result.VolumeTypeName = type.Value;
        result.VolumeId = (string?)element.Element("volume_id");
        result.VolumeTimestamp = (string?)element.Element("volume_ts");
        if (element.Element("package") is { } package)
        {
            result.Package = new Gp5Package
            {
                ContentId = (string?)package.Attribute("content_id"),
                Passcode = Text(package, "passcode", result.Package.Passcode),
                StorageType = (string?)package.Attribute("storage_type"),
                AppPath = (string?)package.Attribute("app_path"),
            };
        }
        if (element.Element("chunk_info") is { } chunkInfo)
        {
            var info = new Gp5ChunkInfo
            {
                ChunkCount = Number(chunkInfo, "chunk_count", 0),
                ScenarioCount = Number(chunkInfo, "scenario_count", 0),
            };
            if (chunkInfo.Element("chunks") is { } chunks)
                foreach (var chunk in chunks.Elements("chunk"))
                    info.Chunks.Add(new Gp5Chunk { Id = Number(chunk, "id", 0), Label = Text(chunk, "label", "") });
            if (chunkInfo.Element("scenarios") is { } scenarios)
            {
                info.Scenarios.DefaultId = Number(scenarios, "default_id", 0);
                foreach (var scenario in scenarios.Elements("scenario"))
                    info.Scenarios.Items.Add(new Gp5Scenario
                    {
                        Id = Number(scenario, "id", 0),
                        Type = Text(scenario, "type", "playmode"),
                        InitialChunkCount = Number(scenario, "initial_chunk_count", 0),
                        Label = Text(scenario, "label", ""),
                        Chunks = scenario.Value.Length == 0 ? "0" : scenario.Value,
                    });
            }
            result.ChunkInfo = info;
        }
        return result;
    }

    private static string Text(XElement element, string name, string fallback) => (string?)element.Attribute(name) ?? fallback;
    private static int Number(XElement element, string name, int fallback) => element.Attribute(name) is { } attribute ? XmlConvert.ToInt32(attribute.Value) : fallback;
    private static void Attribute(XmlWriter writer, string name, int value) => Attribute(writer, name, XmlConvert.ToString(value));
    private static void Attribute(XmlWriter writer, string name, string? value)
    {
        if (value is not null) writer.WriteAttributeString(name, value);
    }
    private static void OptionalAttribute(XmlWriter writer, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value)) writer.WriteAttributeString(name, value);
    }
    private static void Element(XmlWriter writer, string name, string? value)
    {
        if (value is not null) writer.WriteElementString(name, value);
    }
}
