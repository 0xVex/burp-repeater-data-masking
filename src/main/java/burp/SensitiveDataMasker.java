package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.*;
import javax.swing.border.TitledBorder;

public class SensitiveDataMasker implements IBurpExtender, IMessageEditorTabFactory {
    
    private static final String EXTENSION_NAME = "Sensitive Data Masker";
    private static final String EXTENSION_VERSION = "1.0.0";
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    // Masking patterns for different sensitive data types
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "(eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*)", 
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SESSION_COOKIE_PATTERN = Pattern.compile(
        "((?:session|sess|sessionid|jsessionid|phpsessid|sid)=[A-Za-z0-9+/=_-]+)", 
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern AUTH_HEADER_PATTERN = Pattern.compile(
        "(Authorization:\\s*(?:Bearer|Basic|Digest)\\s+[A-Za-z0-9+/=_-]+)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "((?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[:=]\\s*['\"]?)([A-Za-z0-9+/=_-]{16,})(['\"]?)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerMessageEditorTabFactory(this);
        
        // Extension startup information
        callbacks.printOutput("========================================");
        callbacks.printOutput(EXTENSION_NAME + " v" + EXTENSION_VERSION);
        callbacks.printOutput("========================================");
        callbacks.printOutput("Extension loaded successfully!");
        callbacks.printOutput("Added 'Masked View' tab to Repeater");
        callbacks.printOutput("Ready to mask sensitive data for screenshots");
        callbacks.printOutput("========================================");
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new SensitiveDataMaskerTab(controller, editable);
    }

    private class SensitiveDataMaskerTab implements IMessageEditorTab {
        private boolean editable;
        private IMessageEditor messageEditor;
        private byte[] currentMessage;
        private IMessageEditorController controller;
        private JPanel panel;
        private JToggleButton maskToggle;
        private JButton settingsButton;
        private JCheckBox maskJWT;
        private JCheckBox maskCookies;
        private JCheckBox maskAuthHeaders;
        private JCheckBox maskApiKeys;
        private JCheckBox enableCustomPatterns;
        private JTextArea customPatternsArea;
        private List<Pattern> compiledCustomPatterns = new ArrayList<>();
        private boolean isMasked = false;
        private byte[] originalMessage;
        private boolean isRequest;

        public SensitiveDataMaskerTab(IMessageEditorController controller, boolean editable) {
            this.controller = controller;
            this.editable = editable;
            // Create message editor with syntax highlighting but no controller to avoid nested tabs
            this.messageEditor = callbacks.createMessageEditor(null, editable);
            
            setupUI();
        }

        private void setupUI() {
            panel = new JPanel(new BorderLayout());
            
            // Create simple control panel with just toggle and settings buttons
            JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            controlPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
            controlPanel.setBackground(null);
            controlPanel.setPreferredSize(new Dimension(0, 40));
            
            // Main toggle button
            maskToggle = new JToggleButton("Enable Masking");
            maskToggle.setToolTipText("Toggle masking of sensitive information for screenshots");
            maskToggle.addActionListener(e -> toggleMasking());
            
            // Settings button to open configuration dialog
            settingsButton = new JButton("Settings...");
            settingsButton.setToolTipText("Configure which data types to mask and add custom patterns");
            settingsButton.addActionListener(e -> showSettingsDialog());
            
            // Initialize checkboxes with default values (not added to UI directly)
            maskJWT = new JCheckBox("JWT Tokens", true);
            maskCookies = new JCheckBox("Session Cookies", true);
            maskAuthHeaders = new JCheckBox("Auth Headers", true);
            maskApiKeys = new JCheckBox("API Keys", true);
            enableCustomPatterns = new JCheckBox("Enable Custom Patterns", false);
            
            // Initialize custom patterns area with example template
            customPatternsArea = new JTextArea(6, 40);
            customPatternsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            customPatternsArea.setToolTipText("Enter regex patterns, one per line. Use parentheses to capture the part to keep.");
            
            // Add example patterns as template
            String examplePatterns = "# Example custom patterns - modify or replace as needed\n" +
                "# OAuth and API credentials\n" +
                "(client_secret=)[A-Za-z0-9-_]+\n" +
                "(refresh_token=)[A-Za-z0-9+/=]+\n" +
                "\n" +
                "# Database credentials\n" +
                "(password=)[A-Za-z0-9!@#$%^&*]+\n" +
                "(db_password=)[A-Za-z0-9!@#$%^&*]+\n" +
                "\n" +
                "# Personal information\n" +
                "(ssn=)\\d{3}-\\d{2}-\\d{4}\n" +
                "(email=)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}";
            
            customPatternsArea.setText(examplePatterns);
            
            controlPanel.add(maskToggle);
            controlPanel.add(settingsButton);
            
            panel.add(controlPanel, BorderLayout.NORTH);
            panel.add(messageEditor.getComponent(), BorderLayout.CENTER);
        }

        private void showSettingsDialog() {
            JDialog settingsDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(panel), "Masking Settings", true);
            settingsDialog.setLayout(new BorderLayout());
            
            // Create main panel
            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            
            // Built-in patterns section
            JPanel builtInPanel = new JPanel();
            builtInPanel.setLayout(new BoxLayout(builtInPanel, BoxLayout.Y_AXIS));
            builtInPanel.setBorder(BorderFactory.createTitledBorder("Built-in Patterns"));
            
            builtInPanel.add(maskJWT);
            builtInPanel.add(maskCookies);
            builtInPanel.add(maskAuthHeaders);
            builtInPanel.add(maskApiKeys);
            
            // Custom patterns section
            JPanel customPanel = new JPanel(new BorderLayout());
            customPanel.setBorder(BorderFactory.createTitledBorder("Custom Regex Patterns"));
            
            customPanel.add(enableCustomPatterns, BorderLayout.NORTH);
            
            JScrollPane scrollPane = new JScrollPane(customPatternsArea);
            scrollPane.setPreferredSize(new Dimension(400, 150));
            customPanel.add(scrollPane, BorderLayout.CENTER);
            
            JLabel helpLabel = new JLabel("<html><i>" +
                "Pattern Format: Use parentheses to capture what to keep, everything else gets masked.");
            helpLabel.setFont(helpLabel.getFont().deriveFont(10f));
            helpLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
            customPanel.add(helpLabel, BorderLayout.SOUTH);
            
            // Buttons panel
            JPanel buttonPanel = new JPanel(new FlowLayout());
            JButton loadExamplesButton = new JButton("Load Examples");
            JButton clearButton = new JButton("Clear");
            JButton okButton = new JButton("OK");
            JButton cancelButton = new JButton("Cancel");
            
            loadExamplesButton.addActionListener(e -> {
                String examplePatterns = "# Example custom patterns - modify or replace as needed\n" +
                    "# OAuth and API credentials\n" +
                    "(client_secret=)[A-Za-z0-9-_]+\n" +
                    "(refresh_token=)[A-Za-z0-9+/=]+\n" +
                    "\n" +
                    "# Database credentials\n" +
                    "(password=)[A-Za-z0-9!@#$%^&*]+\n" +
                    "(db_password=)[A-Za-z0-9!@#$%^&*]+\n" +
                    "\n" +
                    "# Personal information\n" +
                    "(ssn=)\\d{3}-\\d{2}-\\d{4}\n" +
                    "(email=)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}";
                customPatternsArea.setText(examplePatterns);
            });
            
            clearButton.addActionListener(e -> customPatternsArea.setText(""));
            
            okButton.addActionListener(e -> {
                // Apply settings and refresh masking if active
                compileCustomPatterns();
                if (isMasked) {
                    applyMasking();
                }
                settingsDialog.dispose();
            });
            
            cancelButton.addActionListener(e -> settingsDialog.dispose());
            
            // Left side buttons
            JPanel leftButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            leftButtonPanel.add(loadExamplesButton);
            leftButtonPanel.add(clearButton);
            
            // Right side buttons
            JPanel rightButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            rightButtonPanel.add(okButton);
            rightButtonPanel.add(cancelButton);
            
            buttonPanel.setLayout(new BorderLayout());
            buttonPanel.add(leftButtonPanel, BorderLayout.WEST);
            buttonPanel.add(rightButtonPanel, BorderLayout.EAST);
            
            // Layout dialog
            mainPanel.add(builtInPanel, BorderLayout.NORTH);
            mainPanel.add(customPanel, BorderLayout.CENTER);
            mainPanel.add(buttonPanel, BorderLayout.SOUTH);
            
            settingsDialog.add(mainPanel);
            settingsDialog.setSize(500, 400);
            settingsDialog.setLocationRelativeTo(panel);
            settingsDialog.setVisible(true);
        }

        private void compileCustomPatterns() {
            compiledCustomPatterns.clear();
            
            if (!enableCustomPatterns.isSelected()) {
                return;
            }
            
            String patternsText = customPatternsArea.getText();
            if (patternsText == null || patternsText.trim().isEmpty()) {
                return;
            }
            
            int validPatterns = 0;
            int totalPatterns = 0;
            String[] patterns = patternsText.split("\n");
            
            for (String patternStr : patterns) {
                patternStr = patternStr.trim();
                if (!patternStr.isEmpty() && !patternStr.startsWith("#")) { // Allow comments with #
                    totalPatterns++;
                    try {
                        Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
                        compiledCustomPatterns.add(pattern);
                        validPatterns++;
                    } catch (PatternSyntaxException e) {
                        // Log invalid patterns but don't break the extension
                        callbacks.printError("Invalid regex pattern: " + patternStr + " - " + e.getMessage());
                    }
                }
            }
            
            // Provide user feedback
            if (totalPatterns > 0) {
                callbacks.printOutput("Custom patterns compiled: " + validPatterns + "/" + totalPatterns + " valid");
                if (validPatterns != totalPatterns) {
                    callbacks.printError((totalPatterns - validPatterns) + " custom pattern(s) failed to compile. Check the Burp error log.");
                }
            }
        }

        private void toggleMasking() {
            if (maskToggle.isSelected()) {
                if (!isMasked && currentMessage != null) {
                    originalMessage = currentMessage.clone();
                    compileCustomPatterns(); // Compile patterns before masking
                    applyMasking();
                    isMasked = true;
                    maskToggle.setText("Disable Masking");
                }
            } else {
                if (isMasked && originalMessage != null) {
                    messageEditor.setMessage(originalMessage, isRequest);
                    currentMessage = originalMessage;
                    isMasked = false;
                    maskToggle.setText("Enable Masking");
                }
            }
        }

        private void applyMasking() {
            if (currentMessage == null) return;
            
            // Performance optimization: Skip masking for very large messages
            if (currentMessage.length > 1024 * 1024) { // 1MB limit
                callbacks.printOutput("Message too large for masking (>1MB). Displaying original content.");
                return;
            }
            
            String messageStr = helpers.bytesToString(currentMessage);
            String maskedStr = messageStr;
            
            // Apply masking based on selected options with clean formatting
            if (maskJWT.isSelected()) {
                maskedStr = JWT_PATTERN.matcher(maskedStr).replaceAll("eyJ***[MASKED_JWT_TOKEN]***");
            }
            
            if (maskCookies.isSelected()) {
                maskedStr = SESSION_COOKIE_PATTERN.matcher(maskedStr).replaceAll("$1***[MASKED_SESSION_COOKIE]***");
            }
            
            if (maskAuthHeaders.isSelected()) {
                maskedStr = AUTH_HEADER_PATTERN.matcher(maskedStr).replaceAll("Authorization:***[MASKED_AUTH_HEADER]***");
            }
            
            if (maskApiKeys.isSelected()) {
                maskedStr = API_KEY_PATTERN.matcher(maskedStr).replaceAll("$1***[MASKED_API_KEY]***$3");
            }
            
            // Apply custom patterns if enabled
            if (enableCustomPatterns.isSelected()) {
                for (Pattern customPattern : compiledCustomPatterns) {
                    try {
                        maskedStr = customPattern.matcher(maskedStr).replaceAll("$1[CUSTOM_MASKED]");
                    } catch (Exception e) {
                        // Log errors but continue with other patterns
                        callbacks.printError("Error applying custom pattern: " + e.getMessage());
                    }
                }
            }
            
            // Set the message while preserving HTTP message structure for syntax highlighting
            byte[] maskedBytes = helpers.stringToBytes(maskedStr);
            messageEditor.setMessage(maskedBytes, isRequest);
        }

        @Override
        public String getTabCaption() {
            return "Masked View";
        }

        @Override
        public Component getUiComponent() {
            return panel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return content != null && content.length > 0;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            // Store the isRequest parameter for proper HTTP syntax highlighting
            this.isRequest = isRequest;
            
            if (content == null) {
                messageEditor.setMessage(null, isRequest);
                currentMessage = null;
                originalMessage = null;
                isMasked = false;
                maskToggle.setSelected(false);
                maskToggle.setText("Enable Masking");
                return;
            }
            
            // Store original message
            originalMessage = content.clone();
            currentMessage = content.clone();
            
            // Reset masking state when new message is loaded
            if (isMasked) {
                isMasked = false;
                maskToggle.setSelected(false);
                maskToggle.setText("Enable Masking");
            }
            
            // Set the message with proper HTTP context for syntax highlighting
            messageEditor.setMessage(content, isRequest);
        }

        @Override
        public byte[] getMessage() {
            // Always return the original message, not the masked version
            // This ensures that masking is only visual and doesn't affect actual requests
            return originalMessage != null ? originalMessage : messageEditor.getMessage();
        }

        @Override
        public boolean isModified() {
            return messageEditor.isMessageModified();
        }

        @Override
        public byte[] getSelectedData() {
            return messageEditor.getSelectedData();
        }
    }
}
