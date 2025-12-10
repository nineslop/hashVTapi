# VirusTotal File Analyzer

Analyze files for viruses via VirusTotal API with automatic hash calculation via `certutil`

![Node.js](https://img.shields.io/badge/Node.js-18.x+-green) ![Windows](https://img.shields.io/badge/Windows-10%2F11-blue)

## Start

#### 1. Install dependencies
`npm install axios dotenv`<br>
`npm install -D typescript ts-node @types/node`

#### 2. Create a .env file
`copy .env.example .env`

#### 3. Run analysis
`npx ts-node main.ts`

## Requirements

Windows 10/11 (for `certutil` to work)<br>
Node.js 18+ ([Node.js](https://nodejs.org/en?spm=a2ty_o01.29997173.0.0.20205171zbW5TA))<br>
VirusTotal API key ([VirusTotalAPI](https://www.virustotal.com/gui/my-apikey?spm=a2ty_o01.29997173.0.0.20205171zbW5TA))

Setting up the .env file
```.env
VIRUSTOTAL_API_KEY=your_key_virustotal
FILE_PATH="Z:\\path\\to\\file.exe"
HASH_ALGORITHM=SHA256
```

## How to launch

#### Basic method
`npx ts-node main.ts`

#### If npx doesn't work
`.\node_modules\.bin\ts-node main.ts`

#### After compiling to JS
`npx tsc`
`node dist/main.js`

## Example output

```
🔍 Calculating SHA256 hash for: Z:\test\file.exe
✅ Hash calculated: a1b2c3d4e5f67890...

☁️ Checking on VirusTotal...

==================================================
🛡️  VIRUSTOTAL ANALYSIS REPORT
==================================================
🔤 File name: installer.exe
.mime File type: Win32 EXE
🔗 Permalink: https://www.virustotal.com/gui/file/a1b2c3d4e5f6...
--------------------------------------------------
🔴 Malicious:  2 (3%)
🟠 Suspicious: 1
🟢 Clean:      65
❓ Undetected: 2
--------------------------------------------------

🚨 SECURITY ALERT: 2 engines detected threats!
⚠️  This file is likely malicious. Do not execute!
==================================================
```

## Important notes
#### API limits

    Free account: 4 requests per minute, 500 per day
    If the limit is exceeded: Error 429 Too Many Requests

#### Safety

    An API key gives you access to your data in VirusTotal.
    Use a separate key for each project.
    Change the key regularly in VirusTotal settings.

#### Restrictions

    Only works on Windows due to a dependency on certutil
    Does not support files larger than 4GB (VirusTotal API limitation)

## Useful commands

#### Check Node.js version
`node -v`

#### Check package installation
`npm list --depth=0`

#### Recreate .env from template
`copy .env.example .env`

#### Clear npm cache
`npm cache clean --force`