package com.burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.regex.Pattern;

public class SensitiveDataMasker implements BurpExtension {
    
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
        "((?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[:=]\\s*['\"]?([A-Za-z0-9+/=_-]{16,})['\"]?)",
        Pattern.CASE_INSENSITIVE
    );
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("Sensitive Data Masker");

        api.extension().registerUnloadingHandler(() ->
            api.logging().logToOutput("Sensitive Data Masker unloaded.")
        );

        api.userInterface().registerHttpRequestEditorProvider(new SensitiveDataMaskerRequestEditorProvider(api));
        api.userInterface().registerHttpResponseEditorProvider(new SensitiveDataMaskerResponseEditorProvider(api));

        api.logging().logToOutput("Sensitive Data Masker extension loaded successfully!");
        api.logging().logToOutput("This extension adds masking capabilities to Repeater tabs for secure screenshots.");
    }
    
    // Request Editor Provider
    private static class SensitiveDataMaskerRequestEditorProvider implements HttpRequestEditorProvider {
        private final MontoyaApi api;
        
        public SensitiveDataMaskerRequestEditorProvider(MontoyaApi api) {
            this.api = api;
        }
        
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
            return new SensitiveDataMaskerRequestEditor(api, creationContext);
        }
    }
    
    // Response Editor Provider  
    private static class SensitiveDataMaskerResponseEditorProvider implements HttpResponseEditorProvider {
        private final MontoyaApi api;
        
        public SensitiveDataMaskerResponseEditorProvider(MontoyaApi api) {
            this.api = api;
        }
        
        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
            return new SensitiveDataMaskerResponseEditor(api, creationContext);
        }
    }
    
    // Request Editor Implementation
    private static class SensitiveDataMaskerRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final MontoyaApi api;
        private final EditorCreationContext creationContext;
        private final SensitiveDataMaskerPanel editorPanel;
        
        public SensitiveDataMaskerRequestEditor(MontoyaApi api, EditorCreationContext creationContext) {
            this.api = api;
            this.creationContext = creationContext;
            this.editorPanel = new SensitiveDataMaskerPanel(api, true);
        }
        
        @Override
        public HttpRequest getRequest() {
            return editorPanel.getRequest();
        }
        
        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            if (requestResponse.request() != null) {
                editorPanel.setOriginalContent(requestResponse.request().toString());
            }
        }
        
        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return true;
        }
        
        @Override
        public String caption() {
            return "Masked View";
        }
        
        @Override
        public Component uiComponent() {
            return editorPanel;
        }
        
        @Override
        public Selection selectedData() {
            return editorPanel.getSelectedData();
        }
        
        @Override
        public boolean isModified() {
            return false;
        }
    }
    
    // Response Editor Implementation
    private static class SensitiveDataMaskerResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final MontoyaApi api;
        private final EditorCreationContext creationContext;
        private final SensitiveDataMaskerPanel editorPanel;
        
        public SensitiveDataMaskerResponseEditor(MontoyaApi api, EditorCreationContext creationContext) {
            this.api = api;
            this.creationContext = creationContext;
            this.editorPanel = new SensitiveDataMaskerPanel(api, false);
        }
        
        @Override
        public HttpResponse getResponse() {
            return editorPanel.getResponse();
        }
        
        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            if (requestResponse.response() != null) {
                editorPanel.setOriginalContent(requestResponse.response().toString());
            }
        }
        
        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse.response() != null;
        }
        
        @Override
        public String caption() {
            return "Masked View";
        }
        
        @Override
        public Component uiComponent() {
            return editorPanel;
        }
        
        @Override
        public Selection selectedData() {
            return editorPanel.getSelectedData();
        }
        
        @Override
        public boolean isModified() {
            return false;
        }
    }
    
    // Main Panel with Masking Logic
    private static class SensitiveDataMaskerPanel extends JPanel {
        private final boolean isRequest;
        private final HttpRequestEditor requestEditor;
        private final HttpResponseEditor responseEditor;
        private final JToggleButton maskToggle;
        private final JCheckBox maskJWT;
        private final JCheckBox maskCookies;
        private final JCheckBox maskAuthHeaders;
        private final JCheckBox maskApiKeys;
        private String originalContent = "";
        private boolean isMasked = false;

        public SensitiveDataMaskerPanel(MontoyaApi api, boolean isRequest) {
            this.isRequest = isRequest;

            setLayout(new BorderLayout());
            setBorder(new EmptyBorder(5, 5, 5, 5));

            // Create control panel with minimal styling
            JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            controlPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
            controlPanel.setPreferredSize(new Dimension(0, 40));

            // Main toggle button with clean styling
            maskToggle = new JToggleButton("\uD83D\uDD12 Enable Masking");
            maskToggle.setToolTipText("Toggle masking of sensitive information for screenshots while preserving color formatting");
            maskToggle.addActionListener(new MaskToggleListener());

            // Individual masking options
            maskJWT = new JCheckBox("JWT Tokens", true);
            maskCookies = new JCheckBox("Session Cookies", true);
            maskAuthHeaders = new JCheckBox("Auth Headers", true);
            maskApiKeys = new JCheckBox("API Keys", true);

            // Update masking when any checkbox changes
            ActionListener refreshMasking = e -> {
                if (isMasked) {
                    updateDisplay();
                }
            };

            maskJWT.addActionListener(refreshMasking);
            maskCookies.addActionListener(refreshMasking);
            maskAuthHeaders.addActionListener(refreshMasking);
            maskApiKeys.addActionListener(refreshMasking);

            controlPanel.add(maskToggle);
            controlPanel.add(new JSeparator(SwingConstants.VERTICAL));
            controlPanel.add(maskJWT);
            controlPanel.add(maskCookies);
            controlPanel.add(maskAuthHeaders);
            controlPanel.add(maskApiKeys);

            add(controlPanel, BorderLayout.NORTH);

            // Use Burp's native editor so font, colour, and formatting exactly match the Pretty tab
            if (isRequest) {
                requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
                responseEditor = null;
                add(requestEditor.uiComponent(), BorderLayout.CENTER);
            } else {
                responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                requestEditor = null;
                add(responseEditor.uiComponent(), BorderLayout.CENTER);
            }
        }

        public void setOriginalContent(String content) {
            this.originalContent = content != null ? content : "";
            updateDisplay();
        }

        public HttpRequest getRequest() {
            return requestEditor != null ? requestEditor.getRequest() : null;
        }

        public HttpResponse getResponse() {
            return responseEditor != null ? responseEditor.getResponse() : null;
        }

        public Selection getSelectedData() {
            if (requestEditor != null) {
                return requestEditor.selection().orElse(null);
            }
            if (responseEditor != null) {
                return responseEditor.selection().orElse(null);
            }
            return null;
        }

        private String applyMaskingToText(String input) {
            if (input == null || input.isEmpty()) {
                return input;
            }
            String result = input;
            if (maskJWT.isSelected()) {
                result = JWT_PATTERN.matcher(result).replaceAll("eyJ[MASKED_JWT_TOKEN]");
            }
            if (maskCookies.isSelected()) {
                result = SESSION_COOKIE_PATTERN.matcher(result).replaceAll("$1[MASKED_SESSION_COOKIE]");
            }
            if (maskAuthHeaders.isSelected()) {
                result = AUTH_HEADER_PATTERN.matcher(result).replaceAll("Authorization: [MASKED_AUTH_HEADER]");
            }
            if (maskApiKeys.isSelected()) {
                result = API_KEY_PATTERN.matcher(result).replaceAll("$1[MASKED_API_KEY]");
            }
            return result;
        }

        private void updateDisplay() {
            if (originalContent.isEmpty()) {
                return;
            }
            String contentToShow = isMasked ? applyMaskingToText(originalContent) : originalContent;
            SwingUtilities.invokeLater(() -> {
                if (requestEditor != null) {
                    requestEditor.setRequest(HttpRequest.httpRequest(contentToShow));
                } else if (responseEditor != null) {
                    responseEditor.setResponse(HttpResponse.httpResponse(contentToShow));
                }
            });
        }

        private class MaskToggleListener implements ActionListener {
            @Override
            public void actionPerformed(ActionEvent e) {
                isMasked = maskToggle.isSelected();
                maskToggle.setText(isMasked ? "\uD83D\uDD13 Disable Masking" : "\uD83D\uDD12 Enable Masking");
                updateDisplay();
            }
        }
    }
}
