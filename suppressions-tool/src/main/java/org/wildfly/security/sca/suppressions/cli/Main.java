package org.wildfly.security.sca.suppressions.cli;

import org.wildfly.security.sca.suppressions.converter.OwaspDcConverter;
import org.wildfly.security.sca.suppressions.converter.TrivyConverter;
import org.wildfly.security.sca.suppressions.drift.DriftChecker;
import org.wildfly.security.sca.suppressions.migration.OwaspDcMigrator;
import org.wildfly.security.sca.suppressions.resolver.SuppressionResolver;
import org.wildfly.security.sca.suppressions.validator.SuppressionValidator;
import org.wildfly.security.sca.suppressions.validator.ValidationResult;

import java.nio.file.Path;

public final class Main {

    private Main() {}

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        try {
            switch (args[0]) {
                case "validate" -> runValidate(args);
                case "convert-trivy" -> runConvertTrivy(args);
                case "convert-owaspdc" -> runConvertOwaspDc(args);
                case "resolve" -> runResolve(args);
                case "check-drift" -> runCheckDrift(args);
                case "migrate" -> runMigrate(args);
                default -> {
                    System.err.println("Unknown command: " + args[0]);
                    printUsage();
                    System.exit(1);
                }
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void runValidate(String[] args) {
        Path input = Path.of(args.length > 1 ? args[1] : "suppressions/suppressions.yaml");
        ValidationResult result = new SuppressionValidator().validate(input);
        result.errors().forEach(e -> System.err.println("ERROR: " + e));
        result.warnings().forEach(w -> System.err.println("WARNING: " + w));
        if (result.hasErrors()) {
            System.err.println("Validation failed with " + result.errors().size() + " error(s)");
            System.exit(1);
        }
        System.out.println("Validation passed" +
                (result.warnings().isEmpty() ? "" : " with " + result.warnings().size() + " warning(s)"));
    }

    private static void runConvertTrivy(String[] args) {
        Path input = Path.of(args.length > 1 ? args[1] : "suppressions/suppressions.yaml");
        Path output = Path.of(args.length > 2 ? args[2] : "suppressions/.trivyignore.yaml");
        new TrivyConverter().convert(input, output);
    }

    private static void runConvertOwaspDc(String[] args) {
        Path input = Path.of(args.length > 1 ? args[1] : "suppressions/suppressions.yaml");
        Path output = Path.of(args.length > 2 ? args[2] : "owasp-suppressions/owasp-suppressions-roundtrip.xml");
        new OwaspDcConverter().convert(input, output);
    }

    private static void runResolve(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: resolve <canonical.yaml> <trivy-scan.json> <output.yaml>");
            System.exit(1);
        }
        new SuppressionResolver().resolve(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
    }

    private static void runCheckDrift(String[] args) {
        Path xml = Path.of(args.length > 1 ? args[1] : "owasp-suppressions/owasp-suppressions.xml");
        Path yaml = Path.of(args.length > 2 ? args[2] : "suppressions/suppressions.yaml");
        boolean drifted = new DriftChecker().checkDrift(xml, yaml);
        if (drifted) {
            System.err.println("DRIFT DETECTED");
            System.exit(1);
        }
        System.out.println("OK — no drift detected");
    }

    private static void runMigrate(String[] args) {
        Path input = Path.of(args.length > 1 ? args[1] : "owasp-suppressions/owasp-suppressions.xml");
        Path output = Path.of(args.length > 2 ? args[2] : "suppressions/suppressions.yaml");
        new OwaspDcMigrator().migrate(input, output);
    }

    private static void printUsage() {
        System.err.println("Usage: suppressions-tool <command> [args...]");
        System.err.println();
        System.err.println("Commands:");
        System.err.println("  validate <yaml>                        Validate canonical YAML");
        System.err.println("  convert-trivy <yaml> <output>          Convert to Trivy .trivyignore.yaml");
        System.err.println("  convert-owaspdc <yaml> <output>        Convert to OWASP DC XML");
        System.err.println("  resolve <yaml> <trivy.json> <output>   Resolve suppressions against scan");
        System.err.println("  check-drift <xml> <yaml>               Check XML/YAML drift");
        System.err.println("  migrate <xml> <output-yaml>            Migrate from OWASP DC XML");
    }
}
