# Proto Client

## Build
Build the executable jar using the following command:
```
mvn clean compile assembly:single

```

## Usage Example

### 1. Create User
```
java -jar proto-client-1.0-SNAPSHOT-jar-with-dependencies.jar --register "<username>" "<name>" "<email>"
```
This also creates the key pair named **"username.public"** and **"username.private"** which will be used in other requests.

### 2. Upload Document
```
java -jar proto-client-1.0-SNAPSHOT-jar-with-dependencies.jar --upload "<username>" "<document path>" "<secret key>" "<key path>"
```

### 3. Share Document
```
java -jar proto-client-1.0-SNAPSHOT-jar-with-dependencies.jar --share "<document id>" "<encrypted key>" "<from username>" "<to username>" "<public key>" "<key path>"
```

### 4. Retrieve Document
```
java -jar proto-client-1.0-SNAPSHOT-jar-with-dependencies.jar --retrieve "<filename>" "<encrypted content>" "<encrypted key>" "<username>" "<key path>"
```