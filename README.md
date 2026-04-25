# keyorix-java

Java SDK for Keyorix — lightweight on-premise secrets manager.

Zero external dependencies. Java 11+.

## Install

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.keyorix</groupId>
    <artifactId>keyorix-java</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick start

```java
import com.keyorix.Keyorix;
import com.keyorix.KeyorixClient;

String token = Keyorix.login("http://your-server:8080", "admin", "password");
KeyorixClient client = Keyorix.newClient("http://your-server:8080", token);

String dbPassword = client.getSecret("db-password", "production");

List<Secret> secrets = client.listSecrets("production");
```

## Environment variables pattern

```java
String token = System.getenv("KEYORIX_TOKEN");
String server = System.getenv("KEYORIX_SERVER");
KeyorixClient client = Keyorix.newClient(server, token);
String dbPassword = client.getSecret("db-password", "production");
```

## API

- Keyorix.login(serverUrl, username, password) -> String
- Keyorix.newClient(serverUrl, token) -> KeyorixClient
- client.getSecret(name, environment) -> String
- client.listSecrets(environment) -> List<Secret>
- client.health() -> boolean

## Exceptions

- KeyorixException — base
- AuthException — authentication failure
- SecretNotFoundException — secret not found

## Requirements

Java 11+, zero external dependencies, Keyorix server v0.1.0+

## License

AGPL-3.0
