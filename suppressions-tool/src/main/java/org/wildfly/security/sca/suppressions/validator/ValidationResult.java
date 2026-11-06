package org.wildfly.security.sca.suppressions.validator;

import java.util.List;

public record ValidationResult(List<String> errors, List<String> warnings) {

    public boolean hasErrors() {
        return !errors.isEmpty();
    }
}
