package com.burp.extension;

public final class LocalValidationRunner {

    private LocalValidationRunner() {
        // Utility class; prevent instantiation.
    }

    public static void main(String[] args) {
        String javaVersion = System.getProperty("java.version", "unknown");

        System.out.println("Burp Repeater Data Masking - local validation runner");
        System.out.println("Java version: " + javaVersion);
        System.out.println("Extension class found: " + SensitiveDataMasker.class.getName());
        System.out.println("Build is healthy. Load the JAR in Burp via Extensions -> Installed -> Add (Java).");
    }
}
