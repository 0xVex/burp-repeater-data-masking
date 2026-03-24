package com.burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

public class SensitiveDataMasker implements BurpExtension {

    private MontoyaApi api;

    // Group 1 = the token itself
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*",
        Pattern.CASE_INSENSITIVE
    );

    // Group 1 = name= (preserved); value consumed without capture
    private static final Pattern SESSION_COOKIE_PATTERN = Pattern.compile(
        "((?:session|sess|sessionid|jsessionid|phpsessid|sid)=)[A-Za-z0-9+/=_-]+",
        Pattern.CASE_INSENSITIVE
    );

    // Group 1 = scheme prefix (preserved); token consumed without capture
    private static final Pattern AUTH_HEADER_PATTERN = Pattern.compile(
        "(Authorization:\\s*(?:Bearer|Basic|Digest)\\s+)[A-Za-z0-9+/=_-]+",
        Pattern.CASE_INSENSITIVE
    );

    // Group 1 = key name + separator (preserved); value consumed without capture
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "((?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[:=]\\s*)['\"]?[A-Za-z0-9+/=_-]{16,}['\"]?",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

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
            return new MaskedRequestEditor(api);
        }
    }

    private static class ResponseEditorProvider implements HttpResponseEditorProvider {
        private final MontoyaApi api;
        ResponseEditorProvider(MontoyaApi api) { this.api = api; }
        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
            return new MaskedResponseEditor(api);
        }
    }

    // ── Editors ───────────────────────────────────────────────────────────────────

    private static class MaskedRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final MaskedPanel panel;
        private HttpRequest currentRequest;

        MaskedRequestEditor(MontoyaApi api) { this.panel = new MaskedPanel(api); }

        @Override public HttpRequest getRequest() { return currentRequest; }
        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            if (rr.request() != null) {
                currentRequest = rr.request();
                panel.setOriginalContent(currentRequest.toString());
            }
        }
        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return true; }
        @Override public String caption()              { return "Masked View"; }
        @Override public Component uiComponent()       { return panel; }
        @Override public Selection selectedData()      { return panel.getSelectedData(); }
        @Override public boolean isModified()          { return false; }
    }

    private static class MaskedResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final MaskedPanel panel;
        private HttpResponse currentResponse;

        MaskedResponseEditor(MontoyaApi api) { this.panel = new MaskedPanel(api); }

        @Override public HttpResponse getResponse() { return currentResponse; }
        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            if (rr.response() != null) {
                currentResponse = rr.response();
                panel.setOriginalContent(currentResponse.toString());
            }
        }
        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return rr.response() != null; }
        @Override public String caption()              { return "Masked View"; }
        @Override public Component uiComponent()       { return panel; }
        @Override public Selection selectedData()      { return panel.getSelectedData(); }
        @Override public boolean isModified()          { return false; }
    }

    // ── Panel ─────────────────────────────────────────────────────────────────────

    private static class MaskedPanel extends JPanel {

        // Static so custom patterns are shared across every open Repeater/Proxy tab
        private static final List<String>  customPatternStrings   = new CopyOnWriteArrayList<>();
        private static final List<Pattern> compiledCustomPatterns = new CopyOnWriteArrayList<>();
        private static final List<WeakReference<MaskedPanel>> allPanels = new CopyOnWriteArrayList<>();

        private final JToggleButton     maskToggle;
        private final JCheckBoxMenuItem miJWT;
        private final JCheckBoxMenuItem miCookies;
        private final JCheckBoxMenuItem miAuthHeaders;
        private final JCheckBoxMenuItem miApiKeys;
        private final JPanel            chipsPanel;
        private final JTextArea         textArea;
        private String  originalContent = "";
        private boolean isMasked        = false;

        MaskedPanel(MontoyaApi api) {
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

            // Patterns dropdown — checkboxes for built-ins + "Add Custom Pattern…"
            miJWT         = new JCheckBoxMenuItem("JWT Tokens",      true);
            miCookies     = new JCheckBoxMenuItem("Session Cookies", true);
            miAuthHeaders = new JCheckBoxMenuItem("Auth Headers",    true);
            miApiKeys     = new JCheckBoxMenuItem("API Keys",        true);

            ActionListener builtInToggle = e -> { if (isMasked) updateDisplay(); };
            miJWT.addActionListener(builtInToggle);
            miCookies.addActionListener(builtInToggle);
            miAuthHeaders.addActionListener(builtInToggle);
            miApiKeys.addActionListener(builtInToggle);

            JMenuItem addCustomItem = new JMenuItem("Add Custom Pattern\u2026");
            addCustomItem.addActionListener(e -> showAddPatternDialog());

            JPopupMenu patternMenu = new JPopupMenu();
            patternMenu.add(new JLabel("  Built-in patterns"));
            patternMenu.addSeparator();
            patternMenu.add(miJWT);
            patternMenu.add(miCookies);
            patternMenu.add(miAuthHeaders);
            patternMenu.add(miApiKeys);
            patternMenu.addSeparator();
            patternMenu.add(addCustomItem);

            JButton patternsBtn = new JButton("Patterns \u25BE");
            patternsBtn.setToolTipText("Toggle built-in patterns or add a custom regex");
            patternsBtn.addActionListener(e ->
                patternMenu.show(patternsBtn, 0, patternsBtn.getHeight())
            );
            toolbar.add(patternsBtn);

            // Chip tags for active custom patterns
            chipsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
            chipsPanel.setOpaque(false);
            toolbar.add(chipsPanel);
            rebuildChips();

            add(toolbar, BorderLayout.NORTH);

            // ── Content area — plain JTextArea avoids recursive nested editor bug ─
            textArea = new JTextArea();
            textArea.setEditable(false);
            textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            textArea.setLineWrap(false);

            JScrollPane scroll = new JScrollPane(textArea);
            scroll.setBorder(null);
            add(scroll, BorderLayout.CENTER);
        }

        private void showAddPatternDialog() {
            JTextField regexField = new JTextField(30);
            JLabel hint = new JLabel(
                "<html><small>Wrap the sensitive value in a capture group to preserve surrounding text.<br>" +
                "Example:&nbsp; <tt>my-token=([A-Za-z0-9]+)</tt></small></html>");
            JPanel inputRow = new JPanel(new BorderLayout(6, 0));
            inputRow.add(new JLabel("Regex:"), BorderLayout.WEST);
            inputRow.add(regexField, BorderLayout.CENTER);
            JPanel wrapper = new JPanel(new BorderLayout(0, 8));
            wrapper.add(inputRow, BorderLayout.CENTER);
            wrapper.add(hint,     BorderLayout.SOUTH);

            int rc = JOptionPane.showConfirmDialog(
                SwingUtilities.getWindowAncestor(this), wrapper,
                "Add Custom Pattern", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (rc != JOptionPane.OK_OPTION) return;

            String raw = regexField.getText().trim();
            if (raw.isEmpty()) return;
            try {
                compiledCustomPatterns.add(Pattern.compile(raw, Pattern.CASE_INSENSITIVE));
                customPatternStrings.add(raw);
                refreshAllPanels();
            } catch (java.util.regex.PatternSyntaxException ex) {
                JOptionPane.showMessageDialog(
                    SwingUtilities.getWindowAncestor(this),
                    "Invalid regex: " + ex.getMessage(), "Pattern Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        private void rebuildChips() {
            chipsPanel.removeAll();
            for (String pat : customPatternStrings) {
                String label = pat.length() > 22 ? pat.substring(0, 19) + "\u2026" : pat;
                JButton chip = new JButton(label + "  \u00d7");
                chip.setToolTipText("Remove: " + pat);
                chip.setFont(chip.getFont().deriveFont(Font.PLAIN, 11f));
                chip.setMargin(new Insets(1, 4, 1, 4));
                chip.addActionListener(e -> {
                    int idx = customPatternStrings.indexOf(pat);
                    if (idx >= 0) {
                        customPatternStrings.remove(idx);
                        compiledCustomPatterns.remove(idx);
                    }
                    refreshAllPanels();
                });
                chipsPanel.add(chip);
            }
            chipsPanel.revalidate();
            chipsPanel.repaint();
        }

        private static void refreshAllPanels() {
            allPanels.removeIf(r -> r.get() == null);
            for (WeakReference<MaskedPanel> ref : allPanels) {
                MaskedPanel p = ref.get();
                if (p != null) {
                    p.rebuildChips();
                    if (p.isMasked) p.updateDisplay();
                }
            }
        }

        void setOriginalContent(String content) {
            this.originalContent = content != null ? content : "";
            updateDisplay();
        }

        Selection getSelectedData() {
            String sel = textArea.getSelectedText();
            if (sel != null && !sel.isEmpty()) {
                return Selection.selection(
                    ByteArray.byteArray(sel.getBytes()),
                    textArea.getSelectionStart(),
                    textArea.getSelectionEnd());
            }
            return null;
        }

        private String applyMasking(String input) {
            if (input == null || input.isEmpty()) return input;
            String result = input;
            if (miJWT.isSelected())
                result = JWT_PATTERN.matcher(result).replaceAll("eyJ[MASKED_JWT_TOKEN]");
            if (miCookies.isSelected())
                result = SESSION_COOKIE_PATTERN.matcher(result).replaceAll("$1[MASKED_COOKIE]");
            if (miAuthHeaders.isSelected())
                result = AUTH_HEADER_PATTERN.matcher(result).replaceAll("$1[MASKED_TOKEN]");
            if (miApiKeys.isSelected())
                result = API_KEY_PATTERN.matcher(result).replaceAll("$1[MASKED_API_KEY]");
            // Custom patterns: mask group 1 if present, otherwise the full match
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
            String text = isMasked ? applyMasking(originalContent) : originalContent;
            SwingUtilities.invokeLater(() -> {
                int caret = textArea.getCaretPosition();
                textArea.setText(text);
                try { textArea.setCaretPosition(Math.min(caret, text.length())); }
                catch (IllegalArgumentException ignored) { textArea.setCaretPosition(0); }
            });
        }
    }
}
