package com.keyorix;

/**
 * Represents a Keyorix project.
 */
public class Project {
    private final long id;
    private final String name;
    private final String description;
    private final String createdAt;

    public Project(long id, String name, String description, String createdAt) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.createdAt = createdAt;
    }

    public long getId()            { return id; }
    public String getName()        { return name; }
    public String getDescription() { return description; }
    public String getCreatedAt()   { return createdAt; }

    @Override
    public String toString() {
        return "Project{id=" + id + ", name='" + name + "'}";
    }
}
