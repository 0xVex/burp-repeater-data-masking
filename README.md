# Sensitive Data Masker - Burp Suite Extension

A Burp Suite extension that adds masking capabilities to the Repeater section, allowing you to hide sensitive information like JWT tokens, session cookies, and API keys when taking screenshots or sharing screen content.

## Features

- **Toggle Masking**: Easy on/off toggle for masking sensitive data
- **Selective Masking**: Choose which types of data to mask:
  - JWT Tokens
  - Session Cookies
  - Authorization Headers  
  - API Keys
  - Custom Regex Patterns
- **Syntax Highlighting**: Preserves Burp's native HTTP syntax coloring and formatting
- **Screenshot Safe**: Perfect for presentations, documentation, and screen sharing
- **Non-destructive**: Original requests/responses remain unchanged
- **Real-time**: Instant masking/unmasking with toggle

## 🛠️ Installation

### Prerequisites
- **Burp Suite Professional or Community Edition** 2023.1+ 
- **Java 21 or later** (**CRITICAL** - Required for both building and running Burp Suite 2023+)
  - Install with: `brew install openjdk@21` (macOS) or download from [Oracle JDK](https://www.oracle.com/java/technologies/javase/jdk21-archive-downloads.html)

### Building the Extension

#### Step 1: Set Burp JAR Path (Choose One)

**Option A: Environment Variable (Recommended)**
```bash
# Set the path to your Burp Suite JAR
export BURP_JAR="/path/to/your/burpsuite_community.jar"

# Common paths:
# macOS:   export BURP_JAR="/Applications/Burp Suite Community Edition.app/Contents/Resources/app/burpsuite_community.jar"
# Windows: set BURP_JAR="C:\Program Files\BurpSuiteCommunity\app\burpsuite_community.jar"
# Linux:   export BURP_JAR="/opt/BurpSuiteCommunity/burpsuite_community.jar"
```

**Option B: Edit build.gradle**
Update line 33 in `build.gradle` with your Burp Suite JAR path.

#### Step 2: Build with Gradle
```bash
# Uses the included Gradle wrapper - no Gradle installation required
./gradlew buildExtension
```

#### Manual Compilation (Alternative)
```bash
# Create build directory
mkdir -p build/classes

# Compile (uses BURP_JAR environment variable)
javac -cp "$BURP_JAR" -d build/classes src/main/java/burp/SensitiveDataMasker.java

# Package JAR
jar cf SensitiveDataMasker.jar -C build/classes burp/
```

### Loading in Burp Suite

1. Open Burp Suite
2. Go to **Extensions** tab
3. Click **Add**
4. Select **Extension type**: Java
5. Choose the compiled JAR file (`SensitiveDataMasker.jar`)
6. Click **Next**

The extension should load successfully and you'll see "Sensitive Data Masker extension loaded successfully!" in the output.

## 📖 Usage

### In Repeater Tab

1. Open any request in **Repeater**
2. You'll see a new **"Masked View"** tab alongside the Raw/Hex tabs
3. Click on the **Masked View** tab
4. Use the masking controls:
   - **Enable Masking**: Toggle to enable/disable masking
   - **Settings...**: Click to open configuration dialog where you can:
     - Select which built-in patterns to mask (JWT, cookies, auth headers, API keys)
     - Enable/disable custom regex patterns
     - Add your own regex patterns with example templates

### Taking Screenshots

1. Enable masking with the toggle button
2. Select the data types you want to hide
3. Take your screenshot or share your screen
4. Toggle off masking to return to original content

## What Gets Masked

### JWT Tokens
- Pattern: `eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`
- Masked as: `eyJ[MASKED_JWT_TOKEN]`

### Session Cookies
- Patterns: `session=`, `sessionid=`, `jsessionid=`, `phpsessid=`, `sid=`
- Masked as: `session=[MASKED_SESSION_COOKIE]`

### Authorization Headers
- Patterns: `Authorization: Bearer`, `Authorization: Basic`, `Authorization: Digest`
- Masked as: `Authorization: [MASKED_AUTH_HEADER]`

### API Keys
- Patterns: `api_key`, `apikey`, `access_token`, `secret_key`
- Masked as: `api_key=[MASKED_API_KEY]`

### Custom Regex Patterns
- **Settings Dialog**: Click "Settings..." button to configure custom patterns
- **Example Templates**: Pre-loaded with common pattern examples you can modify
- **Multi-line support**: Enter multiple patterns, one per line
- **Comments**: Use `#` to add comments in your patterns
- **Pattern Format**: Use parentheses to capture what to keep: `(password=)[A-Za-z0-9]+`
- **Helpful Buttons**:
  - **Load Examples**: Restore example pattern templates
  - **Clear**: Remove all patterns
- **Error handling**: Invalid patterns are logged but don't break masking
- **Masked as**: `password=[CUSTOM_MASKED]`

## Configuration

The extension comes with sensible defaults, but you can customize which data types to mask using the checkboxes in the interface.

## Development

### Project Structure
```
burp/
├── src/main/java/burp/
│   └── SensitiveDataMasker.java  # Main extension code
├── build.gradle                  # Gradle build file  
├── gradlew                       # Gradle wrapper
├── gradle/wrapper/               # Gradle wrapper files
├── LICENSE                       # MIT license
└── README.md                     # Documentation
```

### Using Custom Patterns

**In the Extension UI:**
1. Click the **Settings...** button next to "Enable Masking"
2. In the dialog, check **Enable Custom Patterns**
3. The text area comes pre-loaded with example patterns
4. Modify existing patterns or add your own
5. Use **Load Examples** to restore templates if needed
6. Click **OK** to apply your patterns

**Example Pattern Templates (included):**
```regex
# OAuth and API credentials
(client_secret=)[A-Za-z0-9-_]+
(refresh_token=)[A-Za-z0-9+/=]+

# Database credentials
(password=)[A-Za-z0-9!@#$%^&*]+
(db_password=)[A-Za-z0-9!@#$%^&*]+

# Personal information  
(ssn=)\d{3}-\d{2}-\d{4}
(email=)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
```

**Adding Hardcoded Patterns:**
To add permanent patterns to the extension code, modify the regex patterns in `src/main/java/burp/SensitiveDataMasker.java` and add masking logic in the `applyMasking()` method.

## Troubleshooting

### Common Issues

#### "class file has wrong version" or "invalid source release: 21" Build Error
**Cause**: Your Java version doesn't match Burp Suite's requirements  
**Fix**: Install and configure Java 21+

**macOS (Homebrew):**
```bash
# Install Java 21
brew install openjdk@21

# Add to your shell profile (~/.zshrc, ~/.bash_profile, etc.)
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
export PATH=$JAVA_HOME/bin:$PATH

# Reload your shell or run:
source ~/.zshrc  # or ~/.bash_profile

# Verify installation
java -version  # Should show version 21+
```

**Alternative: Use Gradle with specific Java:**
```bash
# If you have Java 21 installed elsewhere
./gradlew -Dorg.gradle.java.home=/path/to/java21 buildExtension
```

#### Extension Won't Load in Burp Suite
**Cause**: Burp Suite version or Java compatibility  
**Fix**: 
1. Ensure Burp Suite 2023.1+ with Java 21+
2. Check Burp error log: **Extensions → Errors**
3. Verify JAR file isn't corrupted

#### No Masking Occurs
**Cause**: Settings not configured  
**Fix**: 
1. Click "Settings..." button in Masked View tab
2. Enable desired masking patterns
3. Ensure "Enable Masking" toggle is ON

#### Performance Issues
- **Large messages (>1MB)**: Automatically skipped for performance
- **Too many custom patterns**: Limit to essential patterns only
- **Complex regex**: Simplify patterns for better performance
