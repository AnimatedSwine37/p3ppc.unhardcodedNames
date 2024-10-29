# p3ppc.unhardcodedNames
A mod for Persona 3 Portable PC that lets you change some of the game's hardcoded names through external json files.

This is a framework for other mods and does not do anything on its own!

## Usage (For Mod Makers)
- Make this a dependency of your mod
- Create a folder named `NamePatches` in your mod
- Add json patch files into the `NamePatches` folder. See [Patch Files](#patch-files) for valid types.

## Patch Files
The general format of a patch file is a `json` array containing ids and the edited names for each language. Such as 

```json
[
    {
        "Id": 123,
        "English": "English Name",
        "French": "French Name",
        "Italian": "Italian Name",
        "German": "German Name",
        "Spanish": "Spanish Name",
        "Japanese": "Japanese Name",
        "Korean": "Korean Name",
        "SimplifiedChinese": "Simplified Chinese Name",
        "TraditionalChinese": "Traditional Chinese Name",
    },
    {
        "Id": 124,
        "All": "Name for all languages"
    },
]
```

Note that one or multiple languages can be included, any languages that are not included will not have the name changed in it. 
Additionally the `All` language will change the name to be the same thing for every language.

For specifcs on the different types of names you can change see the following sections.

### Item Names
The patch file must be named `ItemNames.json` and should have the `Id` matching the full item ID as seen on the [Amicitia Wiki](https://amicitia.miraheze.org/wiki/Persona_3_Portable/All_Items).

For example, to change the English name of the "Shinjiro Tuxedo", which is item 646, you would have

```json
[
    {
        "Id": 646,
        "English": "New outfit name"
    }
]
```

### Others
TODO add documentation for these.

There are:
- SLinkNames.json
- CharacterNames.json
- Text.json
- Glossary.json