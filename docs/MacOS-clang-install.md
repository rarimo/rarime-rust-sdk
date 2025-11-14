# Installing Standalone Clang on macOS

Start by downloading the official Clang `.dmg` and attempting a standard installation:  
**[Download from official site
](https://download.developer.apple.com/Developer_Tools/Command_Line_Tools_for_Xcode_16.1/Command_Line_Tools_for_Xcode_16.1.dmg)**

- If the installation succeeds without errors, you can skip to **Step 4** to verify the installation.
- If an error occurs due to macOS version restrictions, follow the steps below to modify the installer and complete the
  installation successfully.

# Installing Standalone Clang on macOS (When the Default Installer Fails)

If you encounter issues installing **Standalone Clang** due to macOS version restrictions, you can manually adjust the
installer package.  
Follow the steps below.

---

## 1. Extract the `.pkg` File

1. Mount downloaded `.dmg` and locate the `.pkg` inside.
2. Extract the contents of the package:

```bash
pkgutil --expand path_to_file.pkg extracted_pkg/
```

## 2. Modify the Distribution File

Inside the extracted package, locate the Distribution file.
Edit it and update the allowed macOS versions:

```xml

<allowed-os-versions>
    <os-version before="27.0" min="14.0"/>
</allowed-os-versions>

```

Save the file.

## 3. Repack the Modified Package

```bash

pkgutil --flatten extracted_pkg/ fixed_clang.pkg

```

Install fixed_clang.pkg normally.

## 4. Verify Your Command Line Tools Path

```bash

xcode-select -p

Expected output:

/Library/Developer/CommandLineTools
```

## 5. Check Clang and GCC Aliases

```bash

  username@devicename ~ % gcc --version
 
  Apple clang version 16.0.0 (clang-1600.3.9.4)
  Target: arm64-apple-darwin
  Thread model: posix
  InstalledDir: /Library/Developer/CommandLineTools/usr/bin
     
  username@devicename ~ clang --version
     
  Apple clang version 16.0.0 (clang-1600.3.9.4)
  Target: arm64-apple-darwin
  Thread model: posix
  InstalledDir: /Library/Developer/CommandLineTools/usr/bin
```
