package com.keyorix;

/**
 * Represents a secret returned by the Keyorix API.
 */
public class Secret {
    private final long id;
    private final String name;
    private final String type;
    private final String environment;
    private final long projectId;
    private final String createdAt;

    public Secret(long id, String name, String type, String environment, long projectId, String createdAt) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.environment = environment;
        this.projectId = projectId;
        this.createdAt = createdAt;
    }

    public long getId()          { return id; }
    public String getName()      { return name; }
    public String getType()      { return type; }
    public String getEnvironment() { return environment; }
    public long getProjectId()   { return projectId; }
    public String getCreatedAt() { return createdAt; }

    @Override
    public String toString() {
        return "Secret{id=" + id + ", name='" + name + "', type='" + type + "', environment='" + environment + "'}";
    }
}
