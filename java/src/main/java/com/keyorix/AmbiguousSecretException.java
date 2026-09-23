package com.keyorix;

import java.util.List;

/**
 * Thrown by {@link KeyorixClient#getSecretScoped} when a secret name matches
 * more than one secret within a project+environment scope. Never guessed
 * which one was meant — {@link #getIds()} lists every matching secret ID.
 */
public class AmbiguousSecretException extends KeyorixException {
    private static final long serialVersionUID = 1L;

    private final List<Long> ids;

    public AmbiguousSecretException(String message, List<Long> ids) {
        super(message);
        this.ids = ids;
    }

    /** Every secret ID that matched the ambiguous name. */
    public List<Long> getIds() { return ids; }
}
