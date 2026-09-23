package com.keyorix;

/**
 * Represents an environment scoped to a project. Environment names are
 * unique within one project, not globally — the same name (e.g. "prod") can
 * legitimately exist in more than one project.
 */
public class Environment {
    private final long id;
    private final long projectId;
    private final String name;

    public Environment(long id, long projectId, String name) {
        this.id = id;
        this.projectId = projectId;
        this.name = name;
    }

    public long getId()        { return id; }
    public long getProjectId() { return projectId; }
    public String getName()    { return name; }

    @Override
    public String toString() {
        return "Environment{id=" + id + ", projectId=" + projectId + ", name='" + name + "'}";
    }
}
