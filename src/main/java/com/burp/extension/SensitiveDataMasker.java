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
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

public class SensitiveDataMasker implements BurpExtension {

    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SESSION_COOKIE_PATTERN = Pattern.compile(
        "((?:session|sess|sessionid|jsessionid|phpsessid|sid)=)[A-Za-z0-9+/=_-]+",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern AUTH_HEADER_PATTERN = Pattern.compile(
        "(Authorization:\\s*(?:Bearer|Basic|Digest)\\s+)[A-Za-z0-9+/=._-]+",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "((?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[:=]\\s*)['\"]?[A-Za-z0-9+/=_-]{16,}['\"]?",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Sensitive Data Masker");

        api.extension().registerUnloadingHandler(() ->
            api.logging().logToOutput("Sensitive Data Masker unloaded.")
        );

        api.userInterface().registerHttpRequestEditorProvider(new RequestEditorProvider(api));
        api.userInterface().registerHttpResponseEditorProvider(new ResponseEditorProvider(api));

        api.logging().logToOutput("Sensitive Data Masker extension loaded successfully!");
    }

    // ── Providers ─────────────────────────────────────────────────────────────────

    private static class RequestEditorProvider implements HttpRequestEditorProvider {
        private final MontoyaApi api;
        RequestEditorProvider(MontoyaApi api) { this.api = api; }

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
            // When our extension calls createHttpRequestEditor() internally, Burp
            // sets toolSource to EXTENSIONS.  Return a no-op stub to break recursion.
            if (ctx.toolSource().isFromTool(ToolType.EXTENSIONS)) return new NoOpRequestEditor();
            return new MaskedRequestEditor(api);
        }
    }

    private static class ResponseEditorProvider implements HttpResponseEditorProvider {
        private final MontoyaApi api;
        ResponseEditorProvider(MontoyaApi api) { this.api = api; }

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
            if (ctx.toolSource().isFromTool(ToolType.EXTENSIONS)) return new NoOpResponseEditor();
            return new MaskedResponseEditor(api);
        }
    }

    // ── No-op stubs (never shown — isEnabledFor always returns false) ─────────────

    private static class NoOpRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final JPanel empty = new JPanel();
        @Override public HttpRequest getRequest() { return null; }
        @Override public void setRequestResponse(HttpRequestResponse rr) {}
        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return false; }
        @Override public String caption()         { return ""; }
        @Override public Component uiComponent()  { return empty; }
        @Override public Selection selectedData() { return null; }
        @Override public boolean isModified()     { return false; }
    }

    private static class NoOpResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final JPanel empty = new JPanel();
        @Override public HttpResponse getResponse() { return null; }
        @Override public void setRequestResponse(HttpRequestResponse rr) {}
        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return false; }
        @Override public String caption()         { return ""; }
        @Override public Component uiComponent()  { return empty; }
        @Override public Selection selectedData() { return null; }
        @Override public boolean isModified()     { return false; }
    }

    // ── Editors ───────────────────────────────────────────────────────────────────

    private static class MaskedRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final MaskedPanel panel;
        private HttpRequest currentRequest;

        MaskedRequestEditor(MontoyaApi api) { this.panel = new MaskedPanel(api, true); }

        @Override public HttpRequest getRequest() { return currentRequest; }
        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            if (rr.request() != null) {
                currentRequest = rr.request();
                panel.setOriginalContent(currentRequest.toString());
            }
        }
        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return true; }
        @Override public String caption()         { return "Masked View"; }
        @Override public Component uiComponent()  { return panel; }
        @Override public Selection selectedData() { return panel.getSelectedData(); }
        @Override public boolean isModified()     { return false; }
    }

    private static class MaskedResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final MaskedPanel panel;
        private HttpResponse currentResponse;

        MaskedResponseEditor(MontoyaApi api) { this.panel = new MaskedPanel(api, false); }

        @Override public HttpResponse getResponse() { return currentResponse; }
        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            if (rr.response() != null) {
                currentResponse = rr.response();
                panel.setOriginalContent(currentResponse.toString());
            }
        }
        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return rr.response() != null; }
        @Override public String caption()         { return "Masked View"; }
        @Override public Component uiComponent()  { return panel; }
        @Override public Selection selectedData() { return panel.getSelectedData(); }
        @Override public boolean isModified()     { return false; }
    }

    // ── Panel ─────────────────────────────────────────────────────────────────────

    private static class MaskedPanel extends JPanel {

        // Shared across all open Masked View tabs so custom patterns apply everywhere
        private static volatile String customPatternsText = "";
        private static volatile List<Pattern> compiledCustomPatterns = new ArrayList<>();
        private static final List<WeakReference<MaskedPanel>> allPanels = new CopyOnWriteArrayList<>();

        private final JToggleButton maskToggle;
        private final JCheckBox     cbJWT;
        private final JCheckBox     cbCookies;
        private final JCheckBox     cbAuthHeaders;
        private final JCheckBox     cbApiKeys;

        // Native Burp editor — identical rendering to Pretty/Raw tabs
        private final HttpRequestEditor  requestEditor;
        private final HttpResponseEditor responseEditor;
        private String  originalContent = "";
        private boolean isMasked        = false;

        MaskedPanel(MontoyaApi api, boolean isRequest) {
            allPanels.add(new WeakReference<>(this));
            setLayout(new BorderLayout());

            // ── Toolbar ──────────────────────────────────────────────────────────
            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

            maskToggle = new JToggleButton("\uD83D\uDD12 Enable Masking");
            maskToggle.addActionListener(e -> {
                isMasked = maskToggle.isSelected();
                maskToggle.setText(isMasked ? "\uD83D\uDD13 Disable Masking" : "\uD83D\uDD12 Enable Masking");
                updateDisplay();
            });
            toolbar.add(maskToggle);

            cbJWT         = new JCheckBox("JWT Tokens",      true);
            cbCookies     = new JCheckBox("Session Cookies", true);
            cbAuthHeaders = new JCheckBox("Auth Headers",    true);
            cbApiKeys     = new JCheckBox("API Keys",        true);

            ActionListener builtInToggle = e -> { if (isMasked) updateDisplay(); };
            cbJWT.addActionListener(builtInToggle);
            cbCookies.addActionListener(builtInToggle);
            cbAuthHeaders.addActionListener(builtInToggle);
            cbApiKeys.addActionListener(builtInToggle);

            JMenuItem editCustomItem = new JMenuItem("Edit Custom Patterns\u2026");
            editCustomItem.addActionListener(e -> showCustomPatternsDialog());

            // JPanel wrappers prevent the popup from auto-closing when a checkbox is toggled
            JPopupMenu patternMenu = new JPopupMenu();
            patternMenu.add(new JLabel("  Built-in patterns"));
            patternMenu.addSeparator();
            patternMenu.add(checkboxRow(cbJWT));
            patternMenu.add(checkboxRow(cbCookies));
            patternMenu.add(checkboxRow(cbAuthHeaders));
            patternMenu.add(checkboxRow(cbApiKeys));
            patternMenu.addSeparator();
            patternMenu.add(editCustomItem);

            JButton patternsBtn = new JButton("Patterns \u25BE");
            patternsBtn.setToolTipText("Toggle built-in patterns or add custom regex patterns");
            patternsBtn.addActionListener(e ->
                patternMenu.show(patternsBtn, 0, patternsBtn.getHeight())
            );
            toolbar.add(patternsBtn);
            add(toolbar, BorderLayout.NORTH);

            // ── Native Burp editor ────────────────────────────────────────────────
            // Recursion is prevented cleanly: our providers check EditorCreationContext
            // .toolSource().isFromTool(ToolType.EXTENSIONS) and return a no-op stub
            // when Burp calls them as part of this createHttpRequest/ResponseEditor call.
            if (isRequest) {
                requestEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
                responseEditor = null;
            } else {
                responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                requestEditor  = null;
            }
            Component innerComp = isRequest ? requestEditor.uiComponent() : responseEditor.uiComponent();
            add(innerComp, BorderLayout.CENTER);
        }

        // Wraps a JCheckBox in a panel so clicking it does not dismiss the popup menu
        private static JPanel checkboxRow(JCheckBox cb) {
            JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            p.setOpaque(false);
            p.add(cb);
            return p;
        }

        private void showCustomPatternsDialog() {
            JTextArea textArea = new JTextArea(customPatternsText.replace(",", ",\n"), 6, 36);
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(false);
            JTextArea hint = new JTextArea(
                "One regex per line. Full match is replaced with [MASKED].\n" +
                "Use a capture group () to preserve surrounding text.\n" +
                "Example:  token=([A-Za-z0-9]+)  masks the value, keeps 'token='");
            hint.setEditable(false);
            hint.setOpaque(false);
            hint.setLineWrap(true);
            hint.setWrapStyleWord(true);
            hint.setFont(UIManager.getFont("Label.font"));
            JPanel wrapper = new JPanel(new BorderLayout(0, 8));
            wrapper.add(new JScrollPane(textArea), BorderLayout.CENTER);
            wrapper.add(hint, BorderLayout.SOUTH);

            int rc = JOptionPane.showConfirmDialog(
                SwingUtilities.getWindowAncestor(this), wrapper,
                "Custom Patterns", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (rc != JOptionPane.OK_OPTION) return;

            // Normalise: newlines and commas both act as separators
            String raw = textArea.getText().replace("\n", ",");
            syncAndRefresh(raw);
        }

        private static void syncAndRefresh(String newText) {
            customPatternsText = newText;
            // Compile once here; applyMasking() uses the cached list
            List<Pattern> compiled = new ArrayList<>();
            for (String raw : newText.split(",")) {
                raw = raw.trim();
                if (raw.isEmpty()) continue;
                try {
                    compiled.add(Pattern.compile(raw, Pattern.CASE_INSENSITIVE));
                } catch (java.util.regex.PatternSyntaxException ignored) {}
            }
            compiledCustomPatterns = compiled;
            allPanels.removeIf(r -> r.get() == null);
            for (WeakReference<MaskedPanel> ref : allPanels) {
                MaskedPanel p = ref.get();
                if (p != null && p.isMasked) p.updateDisplay();
            }
        }

        void setOriginalContent(String content) {
            this.originalContent = content != null ? content : "";
            updateDisplay();
        }

        Selection getSelectedData() {
            if (requestEditor  != null) return requestEditor.selection().orElse(null);
            if (responseEditor != null) return responseEditor.selection().orElse(null);
            return null;
        }

        private String applyMasking(String input) {
            if (input == null || input.isEmpty()) return input;
            String result = input;
            // Auth headers must run before JWT so the full token is consumed in one pass,
            // preventing the JWT pattern from partially masking a Bearer token first and
            // then the auth header pattern producing a double-masked result.
            if (cbAuthHeaders.isSelected())
                result = AUTH_HEADER_PATTERN.matcher(result).replaceAll("$1[MASKED_TOKEN]");
            if (cbJWT.isSelected())
                result = JWT_PATTERN.matcher(result).replaceAll("eyJ[MASKED_JWT_TOKEN]");
            if (cbCookies.isSelected())
                result = SESSION_COOKIE_PATTERN.matcher(result).replaceAll("$1[MASKED_COOKIE]");
            if (cbApiKeys.isSelected())
                result = API_KEY_PATTERN.matcher(result).replaceAll("$1[MASKED_API_KEY]");
            // Apply pre-compiled custom patterns (compiled once in syncAndRefresh)
            for (Pattern p : compiledCustomPatterns) {
                result = p.matcher(result).replaceAll(m -> {
                    if (m.groupCount() >= 1 && m.group(1) != null) {
                        String whole = m.group(0);
                        int s = m.start(1) - m.start(0);
                        int e = m.end(1)   - m.start(0);
                        return whole.substring(0, s) + "[MASKED]" + whole.substring(e);
                    }
                    return "[MASKED]";
                });
            }
            return result;
        }

        private void updateDisplay() {
            if (originalContent.isEmpty()) return;
            String content = isMasked ? applyMasking(originalContent) : originalContent;
            SwingUtilities.invokeLater(() -> {
                if (requestEditor != null)
                    requestEditor.setRequest(HttpRequest.httpRequest(content));
                else if (responseEditor != null)
                    responseEditor.setResponse(HttpResponse.httpResponse(content));
            });
        }
    }
}
