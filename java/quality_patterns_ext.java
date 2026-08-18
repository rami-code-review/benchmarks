package benchmarks;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.math.BigDecimal;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertThrows;

class AsyncDataLoader {
    private static final Logger logger = LoggerFactory.getLogger(AsyncDataLoader.class);

    private Data fetchData() {
        return remote.load();
    }

    private Data fallbackData() {
        return Data.empty();
    }

    void loadWithFallback() {
        CompletableFuture.supplyAsync(() -> fetchData())
            .exceptionally(ex -> {
                logger.error("Failed to fetch data", ex);
                return fallbackData();
            });
    }
}

class LockedDataClient {
    private final HttpClientFacade client = new HttpClientFacade();
    private final ReentrantLock lock = new ReentrantLock();

    public Data fetchData() {
        lock.lock();
        try {
            return client.get("/data");
        } finally {
            lock.unlock();
        }
    }
}

@Service
public class ReportService {
    private final DataSource dataSource;

    public ReportService(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public Report generate() {
        return new Report(dataSource.query());
    }
}

class FileImporter {
    private static final Logger logger = LoggerFactory.getLogger(FileImporter.class);

    Record importRecord(Path path) {
        try {
            return parse(Files.readString(path));
        } catch (IOException e) {
            logger.error("IO error", e);
            throw new ServiceException("Failed to read file", e);
        } catch (ParseException e) {
            logger.error("Parse error", e);
            throw new ServiceException("Invalid format", e);
        }
    }

    private Record parse(String raw) throws ParseException {
        return Record.of(raw);
    }
}

class RequestController {
    private static final Logger logger = LoggerFactory.getLogger(RequestController.class);

    ResponseEntity<String> handle(RequestPayload payload) {
        try {
            return ResponseEntity.ok(process(payload));
        } catch (Exception e) {
            logger.error("Error processing request", e);
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    private String process(RequestPayload payload) {
        return payload.body();
    }
}

class AccountRepository {
    private static final Logger logger = LoggerFactory.getLogger(AccountRepository.class);
    private DataSource dataSource;

    Account load(long id) {
        try (Connection conn = dataSource.getConnection()) {
            return readAccount(conn, id);
        } catch (SQLException e) {
            logger.error("Database error", e);
            throw new ServiceException("Failed to process request", e);
        }
    }

    private Account readAccount(Connection conn, long id) throws SQLException {
        return Account.from(conn.createStatement().executeQuery("SELECT 1"));
    }
}

class UserRoster {
    private final List<User> users = new ArrayList<>();

    void pruneExpired() {
        Iterator<User> it = users.iterator();
        while (it.hasNext()) {
            User user = it.next();
            if (user.isExpired()) {
                it.remove();
            }
        }
    }
}

class HttpConnectionFactory {
    private static final int CONNECTION_TIMEOUT_MS = 30_000;

    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setConnectTimeout(CONNECTION_TIMEOUT_MS);
}

class ProfileLocator {
    String cityOf(User user) {
        return Optional.ofNullable(user)
            .map(User::getProfile)
            .map(Profile::getAddress)
            .map(Address::getCity)
            .orElse("Unknown");
    }
}

class NumericFilter {
    private static final Pattern PATTERN = Pattern.compile("\\d+");
    for (String s : items) {
        if (PATTERN.matcher(s).matches()) {
            // ...
        }
    }
}

class ItemJoiner {
    String join(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (String s : items) {
            sb.append(s);
        }
        return sb.toString();
    }
}

class ValueCache {
    private final Object lock = new Object();
    private final Map<String, String> map = new HashMap<>();

    private String computeValue() {
        return UUID.randomUUID().toString();
    }

    String getOrCompute(String key) {
        synchronized (lock) {
            if (!map.containsKey(key)) {
                map.put(key, computeValue());
            }
            return map.get(key);
        }
    }
}

class ConnectionProbe {
    private DataSource dataSource;

    void probe() throws SQLException {
        try (Connection conn = dataSource.getConnection()) {
            // use connection
        }
    }
}

class QueryRunner {
    private DataSource dataSource;

    ResultSet run(String query) throws SQLException {
        try (Connection conn = dataSource.getConnection()) {
            // Use connection
            return conn.createStatement().executeQuery(query);
        }
    }
}

class FileLoader {
    byte[] readAll(File file) throws IOException {
        try (InputStream is = new FileInputStream(file)) {
            return IOUtils.toByteArray(is);
        }
    }
}

@Service
public class OrderService {
    private final PaymentGateway gateway;

    public OrderService(PaymentGateway gateway) {
        this.gateway = gateway;
    }
}

@Service
public class TransferService {
    @Transactional
    public void transfer(Account from, Account to, BigDecimal amount) {
        from.debit(amount);
        to.credit(amount);
    }
}

class ParserTest {
    private final Parser parser = new Parser();
    @Test
    void throwsOnInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> {
            parser.parse("invalid");
        });
    }
}
