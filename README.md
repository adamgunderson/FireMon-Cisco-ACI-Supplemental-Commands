# ACI to FireMon Configuration Transfer Script

A Python script that retrieves configuration data from a Cisco ACI device and uploads it to a FireMon revision. This script is designed to run on a FireMon virtual appliance.

## Purpose

This script extends the functionality of the FireMon device pack for Cisco ACI by retrieving and uploading configuration data from the following Cisco ACI API endpoints:

- `/api/class/datetimeNtpProvider.json`
- `/api/class/syslogRemoteDest.json`
- `/api/class/pkiWebTokenData.json`
- `/api/class/aaaDefaultAuth.json`

## Features

- Authenticates with Cisco ACI and retrieves configuration data
- Authenticates with FireMon API
- Gets the latest revision ID for the device
- Posts the configuration files to FireMon
- Dynamic Python module discovery for FireMon appliances
- Multiple authentication options (command-line, environment variables, prompts)
- Robust error handling and reporting

## Requirements

- Python 3.6 or higher
- `requests` Python package (automatically detected on FireMon appliances)

## Installation

1. Copy the script to your FireMon appliance
2. Make it executable:
   ```bash
   chmod +x aci_firemon_script.py
   ```

## Usage

### Command-line Arguments

```bash
python3 aci_firemon_script.py --aci-host 192.168.101.4 --aci-username admin \
    --firemon-host adam.lab.firemon.com --domain-id 1 --device-id 8
```

### Options

| Option              | Description                             | Required |
|---------------------|-----------------------------------------|----------|
| `--aci-host`        | Cisco ACI hostname or IP                | Yes      |
| `--aci-username`    | Cisco ACI username                      | Yes      |
| `--aci-password`    | Cisco ACI password                      | Yes*     |
| `--firemon-host`    | FireMon hostname or IP                  | Yes      |
| `--firemon-username`| FireMon username                        | Yes      |
| `--firemon-password`| FireMon password                        | Yes*     |
| `--domain-id`       | FireMon domain ID                       | Yes      |
| `--device-id`       | FireMon device ID                       | Yes      |
| `--no-prompt`       | Don't prompt for missing credentials    | No       |
| `--help`            | Show help message and exit              | No       |

*\* If not provided via command line, the script will prompt for them unless `--no-prompt` is used*

### Environment Variables

You can also use environment variables to provide credentials:

```bash
export ACI_HOST=192.168.101.4
export ACI_USERNAME=admin
export ACI_PASSWORD=yourpassword
export FIREMON_HOST=adam.lab.firemon.com
export FIREMON_USERNAME=firemon
export FIREMON_PASSWORD=firemon
export FIREMON_DOMAIN_ID=1
export FIREMON_DEVICE_ID=8

python3 aci_firemon_script.py
```

### Interactive Mode

If you don't provide all required credentials via command-line arguments or environment variables, the script will prompt for them:

```bash
python3 aci_firemon_script.py --domain-id 1 --device-id 8
```

This will prompt for ACI and FireMon connection details.

### Non-interactive Mode

For automation, use the `--no-prompt` flag to prevent the script from prompting for missing credentials:

```bash
python3 aci_firemon_script.py --no-prompt --aci-host 192.168.101.4 --domain-id 1 --device-id 8
```

This will fail if any required credentials are missing.

## Authentication Priority

The script looks for credentials in this order:

1. Command-line arguments
2. Environment variables
3. Interactive prompts (if not disabled)
4. Hard-coded values (if uncommented in the script)

## Customization

For testing or development environments, you can uncomment and modify the hard-coded credentials at the top of the script. **This is not recommended for production use.**

## Troubleshooting

### Common Issues

1. **Module Import Errors**:
   - The script automatically searches for the `requests` module in various FireMon paths
   - If not found, install it manually: `pip install requests`

2. **Authentication Failures**:
   - Check your username and password
   - Ensure the ACI and FireMon hosts are accessible from the script location

3. **"No revision ID in response from FireMon"**:
   - Verify that the domain ID and device ID are correct
   - Ensure the device exists in FireMon

## Development

To add support for additional ACI API endpoints:

1. Add the endpoint to the `endpoints` dictionary in the `get_aci_data()` function
2. Update the filename used in the `post_files_to_firemon()` function if needed

## License

This script is provided as-is with no warranty. Use at your own risk.
