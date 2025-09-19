package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class SensitiveDataMasker implements BurpExtension, HttpRequestEditorProvider, HttpResponseEditorProvider, ExtensionUnloadingHandler {
    
    private static final String EXTENSION_NAME = "Sensitive Data Masker";
    private static final String EXTENSION_VERSION = "2.0.0";
    
    private MontoyaApi api;
    
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
    public void initialize(MontoyaApi api) {
        this.api = api;
        
        api.extension().setName(EXTENSION_NAME);
        
        // Register editor providers for both requests and responses
        api.userInterface().registerHttpRequestEditorProvider(this);
        api.userInterface().registerHttpResponseEditorProvider(this);
        
        // Register unload handler
        api.extension().registerUnloadingHandler(this);
        
        // Extension startup information
        api.logging().logToOutput("========================================");
        api.logging().logToOutput(EXTENSION_NAME + " v" + EXTENSION_VERSION);
        api.logging().logToOutput("========================================");
        api.logging().logToOutput("Extension loaded successfully!");
        api.logging().logToOutput("Added 'Masked View' tab to Repeater");
        api.logging().logToOutput("Ready to mask sensitive data for screenshots");
        api.logging().logToOutput("========================================");
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new SensitiveDataMaskerEditor(api, true);
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new SensitiveDataMaskerEditor(api, false);
    }

    @Override
    public void extensionUnloaded() {
        api.logging().logToOutput("Sensitive Data Masker extension unloaded cleanly.");
    }

    private static class SensitiveDataMaskerEditor implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {
        
        private final MontoyaApi api;
        private final boolean isRequest;
        private JPanel panel;
        private JToggleButton maskToggle;
        private JButton settingsButton;
        private HttpRequestEditor requestEditor;
        private HttpResponseEditor responseEditor;
        
        // Settings components
        private JCheckBox maskJWT;
        private JCheckBox maskCookies; 
        private JCheckBox maskAuthHeaders;
        private JCheckBox maskApiKeys;
        private JCheckBox enableCustomPatterns;
        private JTextArea customPatternsArea;
        private List<Pattern> compiledCustomPatterns = new ArrayList<>();
        
        // Data storage
        private ByteArray currentMessage;
        private ByteArray originalMessage;
        private boolean isMasked = false;

        public SensitiveDataMaskerEditor(MontoyaApi api, boolean isRequest) {
            this.api = api;
            this.isRequest = isRequest;
            setupUI();
        }

        private void setupUI() {
            panel = new JPanel(new BorderLayout());
            
            // Create control panel with buttons
            JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            controlPanel.setBackground(Color.WHITE);
            controlPanel.setPreferredSize(new Dimension(controlPanel.getPreferredSize().width, 35));
            
            maskToggle = new JToggleButton("Enable Masking");
            maskToggle.addActionListener(e -> toggleMasking());
            
            settingsButton = new JButton("Settings...");
            settingsButton.addActionListener(e -> showSettingsDialog());
            
            // Initialize settings components
            maskJWT = new JCheckBox("JWT Tokens", true);
            maskCookies = new JCheckBox("Session Cookies", true);
            maskAuthHeaders = new JCheckBox("Auth Headers", true);
            maskApiKeys = new JCheckBox("API Keys", true);
            enableCustomPatterns = new JCheckBox("Enable Custom Patterns", false);
            
            // Initialize custom patterns area with examples
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
            
            // Create native Burp editors with perfect syntax highlighting
            if (isRequest) {
                requestEditor = api.userInterface().createHttpRequestEditor();
            } else {
                responseEditor = api.userInterface().createHttpResponseEditor();
            }
            
            // Get the editor component and modify it to prevent nested tabs
            Component editorComponent = isRequest ? requestEditor.uiComponent() : responseEditor.uiComponent();
            
            // Apply anti-nesting fix by hiding tabs if we're already in Masked View context
            editorComponent = applyAntiNestingFix(editorComponent);
            
            panel.add(controlPanel, BorderLayout.NORTH);
            panel.add(editorComponent, BorderLayout.CENTER);
        }

        private Component applyAntiNestingFix(Component editorComponent) {
            // Hide internal tabs to prevent nesting when we're already in "Masked View" context
            hideInternalTabsRecursive(editorComponent);
            return editorComponent;
        }
        
        private void hideInternalTabsRecursive(Component component) {
            if (component instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) component;
                
                // Check if this is the internal editor tabs (Pretty, Raw, Hex)
                if (hasStandardEditorTabs(tabbedPane)) {
                    // Select and show only the Pretty tab, hide the tab bar
                    for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                        String title = tabbedPane.getTitleAt(i);
                        if ("Pretty".equals(title)) {
                            tabbedPane.setSelectedIndex(i);
                            break;
                        }
                    }
                    
                    // Hide the tab header to prevent nested appearance
                    try {
                        tabbedPane.setTabPlacement(JTabbedPane.TOP);
                        // Make tabs invisible by setting height to 0
                        tabbedPane.setUI(new javax.swing.plaf.basic.BasicTabbedPaneUI() {
                            @Override
                            protected int calculateTabAreaHeight(int tabPlacement, int horizRunCount, int maxTabHeight) {
                                return 0; // Hide tab area
                            }
                            @Override
                            protected void paintTab(Graphics g, int tabPlacement, Rectangle[] rects, int tabIndex, Rectangle iconRect, Rectangle textRect) {
                                // Don't paint tabs
                            }
                        });
                    } catch (Exception e) {
                        api.logging().logToOutput("Could not hide internal tabs: " + e.getMessage());
                    }
                }
            }
            
            // Recursively apply to child components
            if (component instanceof Container) {
                Container container = (Container) component;
                for (Component child : container.getComponents()) {
                    hideInternalTabsRecursive(child);
                }
            }
        }
        
        private boolean hasStandardEditorTabs(JTabbedPane tabbedPane) {
            // Check if this tabbed pane has the standard editor tabs (Pretty, Raw, Hex)
            boolean hasPretty = false, hasRaw = false, hasHex = false;
            
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                String title = tabbedPane.getTitleAt(i);
                if ("Pretty".equals(title)) hasPretty = true;
                if ("Raw".equals(title)) hasRaw = true;
                if ("Hex".equals(title)) hasHex = true;
            }
            
            return hasPretty && hasRaw; // Pretty and Raw are essential, Hex might not always be there
        }

        private void showSettingsDialog() {
            JDialog settingsDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Masking Settings", true);
            settingsDialog.setLayout(new BorderLayout());

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
            
            JLabel helpLabel = new JLabel("Pattern Format: Use parentheses to capture what to keep, everything else gets masked.");
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
            settingsDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
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
                if (!patternStr.isEmpty() && !patternStr.startsWith("#")) {
                    totalPatterns++;
                    try {
                        Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
                        compiledCustomPatterns.add(pattern);
                        validPatterns++;
                    } catch (PatternSyntaxException e) {
                        api.logging().logToError("Invalid regex pattern: " + patternStr + " - " + e.getMessage());
                    }
                }
            }
            
            // Provide user feedback
            if (totalPatterns > 0) {
                api.logging().logToOutput("Custom patterns compiled: " + validPatterns + "/" + totalPatterns + " valid");
                if (validPatterns != totalPatterns) {
                    api.logging().logToError((totalPatterns - validPatterns) + " custom pattern(s) failed to compile. Check the extension error log.");
                }
            }
        }

        private void toggleMasking() {
            if (maskToggle.isSelected()) {
                if (!isMasked && currentMessage != null) {
                    originalMessage = currentMessage;
                    compileCustomPatterns();
                    applyMasking();
                    isMasked = true;
                    maskToggle.setText("Disable Masking");
                }
            } else {
                if (isMasked && originalMessage != null) {
                    displayMessage(originalMessage);
                    currentMessage = originalMessage;
                    isMasked = false;
                    maskToggle.setText("Enable Masking");
                }
            }
        }

        private void applyMasking() {
            if (currentMessage == null) return;
            
            // Performance optimization: Skip masking for very large messages
            if (currentMessage.length() > 1024 * 1024) { // 1MB limit
                api.logging().logToOutput("Message too large for masking (>1MB). Displaying original content.");
                return;
            }
            
            String messageStr = currentMessage.toString();
            String maskedStr = messageStr;
            
            // Apply masking based on selected options
            if (maskJWT.isSelected()) {
                maskedStr = JWT_PATTERN.matcher(maskedStr).replaceAll("eyJ***[MASKED_JWT_TOKEN]***");
            }
            
            if (maskCookies.isSelected()) {
                maskedStr = SESSION_COOKIE_PATTERN.matcher(maskedStr).replaceAll("$1***[MASKED_SESSION_COOKIE]***");
            }
            
            if (maskAuthHeaders.isSelected()) {
                maskedStr = AUTH_HEADER_PATTERN.matcher(maskedStr).replaceAll("Authorization: ***[MASKED_AUTH_HEADER]***");
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
                        api.logging().logToError("Error applying custom pattern: " + e.getMessage());
                    }
                }
            }
            
            // Display the masked content with perfect syntax highlighting
            ByteArray maskedBytes = ByteArray.byteArray(maskedStr);
            
            if (isRequest && requestEditor != null) {
                requestEditor.setRequest(HttpRequest.httpRequest(maskedBytes));
            } else if (!isRequest && responseEditor != null) {
                responseEditor.setResponse(HttpResponse.httpResponse(maskedBytes));
            }
        }

        private void displayMessage(ByteArray message) {
            // Update the editor with perfect syntax highlighting
            if (isRequest && requestEditor != null) {
                if (message != null) {
                    requestEditor.setRequest(HttpRequest.httpRequest(message));
                } else {
                    requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray("")));
                }
            } else if (!isRequest && responseEditor != null) {
                if (message != null) {
                    responseEditor.setResponse(HttpResponse.httpResponse(message));
                } else {
                    responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray("")));
                }
            }
        }

        @Override
        public String caption() {
            return "Masked View";
        }

        @Override
        public Component uiComponent() {
            return panel;
        }

        @Override
        public Selection selectedData() {
            if (isRequest && requestEditor != null) {
                return requestEditor.selection().orElse(null);
            } else if (!isRequest && responseEditor != null) {
                return responseEditor.selection().orElse(null);
            }
            return null;
        }

        @Override
        public boolean isModified() {
            return false; // Always return false since masking is view-only
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            if (requestResponse == null) {
                setContents(ByteArray.byteArray(""));
                return;
            }
            
            if (isRequest && requestResponse.request() != null) {
                setContents(requestResponse.request().toByteArray());
            } else if (!isRequest && requestResponse.response() != null) {
                setContents(requestResponse.response().toByteArray());
            } else {
                setContents(ByteArray.byteArray(""));
            }
        }

        public void setContents(ByteArray contents) {
            currentMessage = contents;
            originalMessage = contents;
            isMasked = false;
            
            // Reset toggle state
            if (maskToggle != null) {
                maskToggle.setSelected(false);
                maskToggle.setText("Enable Masking");
            }
            
            displayMessage(contents);
        }

        public ByteArray getContents() {
            // Always return original message - masking is view-only
            return originalMessage != null ? originalMessage : currentMessage;
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (isRequest) {
                return requestResponse != null && requestResponse.request() != null;
            } else {
                return requestResponse != null && requestResponse.response() != null;
            }
        }

        // Required for ExtensionProvidedHttpRequestEditor
        public HttpRequest getRequest() {
            // Return original request - masking is view-only
            if (originalMessage != null && isRequest) {
                return HttpRequest.httpRequest(originalMessage);
            }
            return null;
        }

        public void setRequest(HttpRequest request) {
            if (request != null) {
                setContents(request.toByteArray());
            }
        }

        // Required for ExtensionProvidedHttpResponseEditor  
        public HttpResponse getResponse() {
            // Return original response - masking is view-only
            if (originalMessage != null && !isRequest) {
                return HttpResponse.httpResponse(originalMessage);
            }
            return null;
        }

        public void setResponse(HttpResponse response) {
            if (response != null) {
                setContents(response.toByteArray());
            }
        }
    }
}