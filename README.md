# Burp Repeater Data Masking Extension

A powerful Burp Suite extension that automatically detects and masks sensitive data in HTTP requests and responses, particularly designed for the Repeater tool but also works with Proxy and Intruder.

## Features

- **Automatic Detection**: Identifies common sensitive data patterns including:
  - API keys and tokens (AWS, GitHub, Slack, etc.)
  - Passwords and secrets
  - JWT tokens and session IDs
  - Credit card numbers
  - Social Security Numbers
  - Email addresses and phone numbers

- **Configurable Masking**: 
  - Enable/disable masking by data type
  - Customizable masking character
  - Custom regex patterns support
  - Persistent configuration storage

- **User-Friendly Interface**:
  - Dedicated configuration tab in Burp Suite
  - Save/load configuration
  - Reset to defaults option
  - Real-time configuration updates

- **Multi-Tool Support**:
  - Primary focus on Repeater tool
  - Also works with Proxy and Intruder
  - Non-intrusive operation

## Installation

### From Releases
1. Download the latest JAR file from the [releases page](../../releases/latest)
2. Open Burp Suite
3. Go to `Extensions` → `Installed`
4. Click `Add`
5. Select `Java` as the extension type
6. Choose the downloaded JAR file
7. Click `Next`

### Build from Source
```bash
git clone https://github.com/yourusername/burp-repeater-data-masking.git
cd burp-repeater-data-masking
./gradlew build
```

The built JAR file will be available in `build/libs/burp-repeater-data-masking-1.0.0.jar`

## Usage

1. **Enable the Extension**: After installation, the extension will automatically load and be enabled by default.

2. **Access Configuration**: Go to the `Data Masking` tab in Burp Suite to configure the extension.

3. **Configure Masking Rules**:
   - Toggle different data types on/off
   - Set custom masking character (default: `*`)
   - Add custom regex patterns for specific data types
   - Save your configuration for future sessions

4. **Use with Repeater**: Send requests through the Repeater tool. Sensitive data will be automatically masked in both requests and responses.

## Configuration Options

### Built-in Pattern Types

- **API Keys**: Detects various API key formats including AWS, GitHub, Slack tokens
- **Passwords**: Finds password fields and secret keys
- **Tokens**: Identifies JWT tokens and session IDs  
- **Credit Cards**: Matches major credit card number formats (Visa, MasterCard, Amex, Discover)

### Custom Patterns

Add your own regex patterns for specific data types. Examples:
```regex
# Social Security Number
(?i)social.?security.?number[\s:=]+(\d{3}-?\d{2}-?\d{4})

# Phone Number
(?i)phone[\s:=]+([\\+]?[1-9]?[0-9]{7,15})

# Custom API Key Format
(?i)my-api-key[\s":=]+["']?([a-zA-Z0-9_\\-]{32})["']?
```

## Security Considerations

- **Privacy First**: All masking happens locally within Burp Suite
- **No Data Transmission**: Sensitive data is never sent to external servers
- **Configurable**: You control what gets masked and how
- **Reversible**: Original data is preserved; masking is for display only

## Examples

### Before Masking
```json
{
  "api_key": "sk-1234567890abcdef1234567890abcdef",
  "password": "mySecretPassword123",
  "credit_card": "4111111111111111",
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### After Masking
```json
{
  "api_key": "sk****************************ef",
  "password": "my****************23",
  "credit_card": "41**********1111",
  "jwt": "ey************************************..."
}
```

## Troubleshooting

### Extension Not Loading
- Ensure you're using Java 17 or higher
- Check the Burp Suite error logs in the `Extensions` tab
- Verify the JAR file is not corrupted

### Patterns Not Working
- Check regex syntax in custom patterns
- Ensure the pattern matches your specific data format
- Test patterns with online regex validators

### Performance Issues
- Disable unused pattern types
- Simplify complex custom patterns
- Use more specific patterns to reduce false positives

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/burp-repeater-data-masking/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/burp-repeater-data-masking/wiki)
- **Email**: support@example.com

---

**Disclaimer**: This extension is designed to help protect sensitive data during security testing. Always ensure you comply with your organization's security policies and applicable laws when handling sensitive information.

