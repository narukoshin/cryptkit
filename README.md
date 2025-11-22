# cryptkit

**A tiny, cute, and dangerously over-caffeinated DES & AES toy written in Go**

## What is this thing?

A ridiculously colorful terminal toy that lets you:
- Encrypt/decrypt **text** or **entire files** with **AES** or **3DES**
- Interactive mode with cute checkmarks (thanks to [promptui](https://github.com/manifoldco/promptui))
- Or just throw a YAML config at it and watch it go brrrrr

## Quick Start

### Installation – Choose Your Fighter

#### Option 1: One-liner (if you already have Go)
```bash
go install github.com/narukoshin/cryptkit@latest
```
→ Done. Just type cryptkit in your terminal forever.

Option 2: Manual build (for masochists who love doing everything manually)
```bash
git clone https://github.com/narukoshin/cryptkit.git; cd cryptkit
go build -ldflags="-s -w" -o cryptkit main.go
sudo mv cryptkit /usr/local/bin/
```

Option 3: Precompiled binaries (recommended for 99.9% of humans)

Just go to the Releases page, download the archive that matches your OS, and:
```bash
chmod +x cryptkit
sudo mv cryptkit /usr/local/bin/cryptkit
```

### Config Mode (for the serious gremlins)

Just create a `config.yml` (or any name) and run: ```cryptkit -config config.yml```

#### Config examples

```yaml
# Encrypt a file with 3DES
algorithm: des # aes or des
input: "@my_secret_diary.pdf" # "@" prefix is for reading the files.
operation: encrypt # or "decrypt"
keys:
  - 00112233445566778899AABBCCDDEEFF
  - 102132435465768798A9BACCADAEAF0F
  - FFEEDDCCBBAA99887766554433221100
output_file: my_secret_diary.pdf.cryptkit # output file
```

```yaml
# AES + file in, file out
algorithm: aes
input: "@plaintext.txt"
operation: encrypt
keys:
  - 00112233445566778899AABBCCDDEEFF
output_file: ciphertext.txt
```

```yaml
# AES
algorithm: aes
input: MY NAME IS RALF
operation: encrypt
keys:
  - 00112233445566778899AABBCCDDEEFF
```

### Interactive UI Mode

Just type the command `cryptkit` and follow the prompts.

#### Example

Selecting the algorithm:

<img width="346" height="78" alt="image" src="https://github.com/user-attachments/assets/83bf0310-2443-4239-828d-f56d33afb654" />

Last prompt where you need to select the output type, write to file, or print in the STD.

<img width="430" height="183" alt="image" src="https://github.com/user-attachments/assets/0e246eee-b21a-4d3f-a82d-b605710b7112" />

