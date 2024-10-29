using p3ppc.unhardcodedNames.Configuration;
using p3ppc.unhardcodedNames.Template;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Memory;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using IReloadedHooks = Reloaded.Hooks.ReloadedII.Interfaces.IReloadedHooks;

namespace p3ppc.unhardcodedNames;
/// <summary>
/// Your mod logic goes here.
/// </summary>
public unsafe class Mod : ModBase // <= Do not Remove.
{
    /// <summary>
    /// Provides access to the mod loader API.
    /// </summary>
    private readonly IModLoader _modLoader;

    /// <summary>
    /// Provides access to the Reloaded.Hooks API.
    /// </summary>
    /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
    private readonly IReloadedHooks? _hooks;

    /// <summary>
    /// Provides access to the Reloaded logger.
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Entry point into the mod, instance that created this class.
    /// </summary>
    private readonly IMod _owner;

    /// <summary>
    /// Provides access to this mod's configuration.
    /// </summary>
    private Config _configuration;

    /// <summary>
    /// The configuration of the currently executing mod.
    /// </summary>
    private readonly IModConfig _modConfig;

    private Memory _memory;

    private const string NAME_PATCH_DIR = "NamePatches";

    private IHook<GetNameDelegate> _getItemNameHook;
    private IHook<GetNameDelegate> _getCharacterFullNameHook;
    private IHook<GetNameDelegate> _getCharacterFirstNameHook;
    private IHook<GetNameDelegate> _getSLinkNameHook;
    private IHook<GetTextDelegate> _getTextHook;
    private IHook<GetTextDelegate> _getGlossaryTextHook;

    private Dictionary<int, nuint[]> _itemNames = new();
    private Dictionary<int, nuint[]> _characterFullNames = new();
    private Dictionary<int, nuint[]> _characterFirstNames = new();
    private Dictionary<int, nuint[]> _characterLastNames = new();
    private Dictionary<int, nuint[]> _sLinkNames = new();
    private Dictionary<int, nuint[]> _hardcodedText = new();
    private Dictionary<int, nuint[]> _glossaryText = new();
    private Language* _language;

    private Dictionary<Language, Encoding> _encodings;

    private void SetupEncodings()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        _encodings = new()
        {
            { Language.English, Encoding.UTF8 },
            { Language.French, Encoding.UTF8 },
            { Language.German, Encoding.UTF8 },
            { Language.Italian, Encoding.UTF8 },
            { Language.Japanese, Encoding.Unicode },
            { Language.Korean, Encoding.Unicode },
            { Language.SimplifiedChinese, Encoding.Unicode },
            { Language.TraditionalChinese, Encoding.Unicode },
            { Language.Spanish, Encoding.UTF8 },
        };
    }


    public Mod(ModContext context)
    {
        _modLoader = context.ModLoader;
        _hooks = context.Hooks;
        _logger = context.Logger;
        _owner = context.Owner;
        _configuration = context.Configuration;
        _modConfig = context.ModConfig;
        _memory = Memory.Instance;

        if (!Utils.Initialise(_logger, _configuration, _modLoader))
            return;

        SetupEncodings();

        Utils.SigScan("E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 0F B6 84 ?? ?? ?? ?? ??", "GetItemName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetItemName function at 0x{funcAddress:X}");
            _getItemNameHook = _hooks.CreateHook<GetNameDelegate>(GetItemName, (long)funcAddress).Activate();
        });

        Utils.SigScan("E8 ?? ?? ?? ?? F3 0F 10 0D ?? ?? ?? ?? 8B CF", "GetCharacterFullName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetCharacterFullName function at 0x{funcAddress:X}");
            _getCharacterFullNameHook = _hooks.CreateHook<GetNameDelegate>(GetCharacterFullName, (long)funcAddress).Activate();
        });

        Utils.SigScan("0F 88 ?? ?? ?? ?? 41 51 48 89 14 24", "GetCharacterFirstName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 2);
            Utils.LogDebug($"Found GetCharacterFirstName function at 0x{funcAddress:X}");
            _getCharacterFirstNameHook = _hooks.CreateHook<GetNameDelegate>(GetCharacterFirstName, (long)funcAddress).Activate();
        });

        // TODO find GetCharacterLastName if it even exists (last names don't really seem to be used)
        //Utils.SigScan("E8 ?? ?? ?? ?? EB ?? F3 0F 10 BC 24 ?? ?? ?? ??", "GetCharacterLastName Ptr", address =>
        //{
        //    var funcAddress = Utils.GetGlobalAddress(address + 1);
        //    Utils.LogDebug($"Found GetCharacterLastName function at 0x{funcAddress:X}");
        //    _getCharacterLastNameHook = _hooks.CreateHook<GetNameDelegate>(GetCharacterLastName, (long)funcAddress).Activate();
        //});

        Utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 0F B7 D9 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 3B 5F ?? 72 ?? 8B 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 83 C2 02 E8 ?? ?? ?? ?? C1 E3 06 48 83 C7 08 89 D8", "GetSLinkName", address =>
        {
            _getSLinkNameHook = _hooks.CreateHook<GetNameDelegate>(GetSLinkName, address).Activate();
        });

        Utils.SigScan("48 63 05 ?? ?? ?? ?? 0F 57 F6", "LanguagePtr", address =>
        {
            var languageAddress = Utils.GetGlobalAddress(address + 3);
            Utils.LogDebug($"Found Language at 0x{languageAddress:X}");
            _language = (Language*)languageAddress;
        });

        Utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 8B D9 8B FA 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 63 05 ?? ?? ?? ??", "HardcodedText", address =>
        {
            _getTextHook = _hooks.CreateHook<GetTextDelegate>(GetText, address).Activate();

            // Dump text
            //nuint** text = (nuint**)Utils.GetGlobalAddress(address + 44);
            //for(int i = 0; i < 142; i++)
            //{
            //    byte* ptr = (byte*)text[(int)Language.English][i];
            //    int count = 0;
            //    while (*(ptr + count) != 0)
            //        count++;
            //    var textStr = Encoding.ASCII.GetString(ptr, count);
            //    Utils.Log($"{i} = \"{textStr}\"");
            //}            
        });

        Utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 48 63 F9 48 8D 0D ?? ?? ?? ?? 48 63 DA E8 ?? ?? ?? ?? 48 63 05 ?? ?? ?? ??", "GetGlossaryText", address =>
        {
            _getGlossaryTextHook = _hooks.CreateHook<GetTextDelegate>(GetGlossaryText, address).Activate();

            //Dump text
            //nuint* text = (nuint*)Utils.GetGlobalAddress(address + 76); // Couldn't get it working, just hardcode, who cares...
            //nuint* text = (nuint*)0x14079c930;
            //for (int i = 0; i < 349; i++)
            //{
            //    byte* ptr = (byte*)text[i];
            //    int count = 0;
            //    while (*(ptr + count) != 0)
            //        count++;
            //    var textStr = Encoding.ASCII.GetString(ptr, count);
            //    Utils.Log($"{i} = \"{textStr}\"");
            //}
        });

        _modLoader.ModLoading += OnModLoading;

        foreach (var mod in _modLoader.GetActiveMods().Where(x => x.Generic.ModDependencies.Contains(_modConfig.ModIcon)))
        {
            AddNamesForMod(mod.Generic.ModId);
        }
    }

    private void OnModLoading(IModV1 mod, IModConfigV1 config)
    {
        if (config.ModDependencies.Contains(_modConfig.ModId))
        {
            AddNamesForMod(config.ModId);
        }
    }

    /// <summary>
    /// Adds all of the name patches for a mod
    /// </summary>
    /// <param name="modId">The id of the mod to add patches for</param>
    private void AddNamesForMod(string modId)
    {
        string modDir = _modLoader.GetDirectoryForModId(modId);
        AddNamesFromDir(Path.Combine(modDir, NAME_PATCH_DIR));
    }

    private void DumpText()
    {

    }

    /// <summary>
    /// Adds all of the name patches from a directory
    /// </summary>
    /// <param name="dir">The directory to search for patches in</param>
    private void AddNamesFromDir(string dir)
    {
        AddNamesFromDir<Name, string?>(dir, _itemNames, "ItemNames.json", WriteGenericName);
        AddNamesFromDir<Name, string?>(dir, _sLinkNames, "SLinkNames.json", WriteGenericName);
        AddNamesFromDir<CharacterName, NameParts?>(dir, _characterFullNames, "CharacterNames.json", WriteCharacterName);
        AddNamesFromDir<Name, string?>(dir, _hardcodedText, "Text.json", WriteGenericName);
        AddNamesFromDir<Name, string?>(dir, _glossaryText, "Glossary.json", WriteGenericName);
    }

    /// <summary>
    /// Tries to add a name patch
    /// </summary>
    /// <typeparam name="T1">The expected type of name patch. This should be an <see cref="IName{T2}"/></typeparam>
    /// <typeparam name="T2">The type of name this is for. This is the generic type of the <see cref="IName{T2}"/></typeparam>
    /// <param name="dir">The directory the patch should be in</param>
    /// <param name="namesDict">A list of names that will be added to if there is a patch</param>
    /// <param name="nameFile">The name of the patch file to search for</param>
    /// <param name="WriteName">A method for writing the patched names to memory</param>
    private void AddNamesFromDir<T1, T2>(string dir, Dictionary<int, nuint[]> namesDict, string nameFile, Action<object, Dictionary<int, nuint[]>, int, int> WriteName)
        where T1 : IName<T2>
    {
        var namesPath = Path.Combine(dir, nameFile);
        if (!File.Exists(namesPath)) return;

        var json = File.ReadAllText(namesPath);
        var names = JsonSerializer.Deserialize<List<T1>>(json);
        if (names == null)
        {
            Utils.LogError($"Error parsing names from {namesPath}");
            return;
        }

        foreach (var name in names)
        {
            var id = name.Id;
            var languages = Enum.GetNames(typeof(Language));

            if (!namesDict.ContainsKey(id))
                namesDict[id] = new nuint[languages.Length];

            for (int i = 0; i < languages.Length; i++)
            {
                var langName = name.GetType().GetProperty(languages[i]).GetValue(name);
                if (langName == null && name.All != null)
                    langName = name.All;
                if (langName != null)
                {
                    WriteName(langName, namesDict, id, i);
                }
            }
        }
    }

    /// <summary>
    /// Writes a generic name, that is just a string
    /// </summary>
    /// <param name="langName">The name of the language this is for</param>
    /// <param name="namesDict">The dictionary of names to add this to</param>
    /// <param name="id">The id of the name this is for</param>
    /// <param name="lang">The id of the language this is for</param>
    private void WriteGenericName(object langName, Dictionary<int, nuint[]> namesDict, int id, int lang)
    {
        var address = WriteString((string)langName, (Language)lang);
        namesDict[id][lang] = address;
    }

    /// <summary>
    /// Writes the name of a character. This includes their first, last, and full names
    /// </summary>
    /// <param name="langName">The name of the language this is for</param>
    /// <param name="namesDict">The dictionary of names to add this to</param>
    /// <param name="id">The id of the name this is for</param>
    /// <param name="lang">The id of the language this is for</param>
    private void WriteCharacterName(object langName, Dictionary<int, nuint[]> namesDict, int id, int lang)
    {
        var name = (NameParts)langName;
        if (name.First != null)
        {
            if (!_characterFirstNames.ContainsKey(id))
                _characterFirstNames[id] = new nuint[9];

            var address = WriteString(name.First, (Language)lang);
            _characterFirstNames[id][lang] = address;
        }

        if (name.Last != null)
        {
            if (!_characterLastNames.ContainsKey(id))
                _characterLastNames[id] = new nuint[9];

            var address = WriteString(name.Last, (Language)lang);
            _characterLastNames[id][lang] = address;
        }

        var fullName = name.Full;
        if (fullName == null)
            fullName = $"{(name.First == null ? "" : name.First)} {(name.Last == null ? "" : name.Last)}";

        var fullAddress = WriteString(fullName, (Language)lang);
        _characterFullNames[id][lang] = fullAddress;

    }

    /// <summary>
    /// Writes a string to memory
    /// </summary>
    /// <param name="text">The string to write to memory</param>
    /// <param name="language">The language the string is in</param>
    /// <returns>The address of the string in memory</returns>
    private nuint WriteString(string text, Language language)
    {
        var bytes = _encodings[language].GetBytes(text);
        var address = _memory.Allocate((nuint)bytes.Length).Address;
        _memory.WriteRaw(address, bytes);
        return address;
    }

    private nuint GetItemName(short item)
    {
        if (!_itemNames.TryGetValue(item, out var name))
        {
            return _getItemNameHook.OriginalFunction(item);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getItemNameHook.OriginalFunction(item);

        return langName;
    }

    private nuint GetCharacterFullName(short character)
    {
        if (!_characterFullNames.TryGetValue(character, out var name))
        {
            return _getCharacterFullNameHook.OriginalFunction(character);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getCharacterFullNameHook.OriginalFunction(character);

        return langName;
    }

    private nuint GetCharacterFirstName(short character)
    {
        if (!_characterFirstNames.TryGetValue(character, out var name))
        {
            return _getCharacterFirstNameHook.OriginalFunction(character);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getCharacterFirstNameHook.OriginalFunction(character);

        return langName;
    }

    private nuint GetSLinkName(short sLink)
    {
        if (!_sLinkNames.TryGetValue(sLink, out var name))
        {
            return _getSLinkNameHook.OriginalFunction(sLink);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getSLinkNameHook.OriginalFunction(sLink);

        return langName;
    }

    private nuint GetText(int major, int minor)
    {
        int id = major + minor;
        if (!_hardcodedText.TryGetValue(id, out var text))
        {
            return _getTextHook.OriginalFunction(major, minor);
        }

        var langText = text[(int)*_language];
        if (langText == nuint.Zero)
            return _getTextHook.OriginalFunction(major, minor);

        return langText;
    }

    private nuint GetGlossaryText(int major, int minor)
    {
        int id = major + minor;
        if (!_glossaryText.TryGetValue(id, out var text))
        {
            return _getGlossaryTextHook.OriginalFunction(major, minor);
        }

        var langText = text[(int)*_language];
        if (langText == nuint.Zero)
            return _getGlossaryTextHook.OriginalFunction(major, minor);

        return langText;
    }

    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetNameDelegate(short id);

    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetTextDelegate(int major, int minor);

    private enum Language : int
    {
        Japanese,
        English,
        Korean,
        TraditionalChinese,
        SimplifiedChinese,
        French,
        German,
        Italian,
        Spanish
    }

    #region Standard Overrides
    public override void ConfigurationUpdated(Config configuration)
    {
        // Apply settings from configuration.
        // ... your code here.
        _configuration = configuration;
        _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
    }
    #endregion

    #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public Mod() { }
#pragma warning restore CS8618
    #endregion
}