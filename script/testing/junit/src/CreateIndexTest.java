/**
 * Insert statement tests.
 */

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import org.junit.*;

import javax.xml.transform.Result;

import static org.junit.Assert.assertEquals;

@SuppressWarnings("ALL")
public class CreateIndexTest extends TestUtility {
    private static final int NUM_EXTRA_THREADS = 2;

    private Connection conn;
    private Connection[] thread_conn = new Connection[NUM_EXTRA_THREADS];

    private static final String SQL_DROP_TABLE =
            "DROP TABLE IF EXISTS tbl;";

    private static final String SQL_CREATE_TABLE =
            "CREATE TABLE tbl (" +
                    "c1 int, " +
                    "c2 int," +
                    "c3 int);";

    /**
     * Initialize the database and table for testing
     */
    private void initDatabase() throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute(SQL_DROP_TABLE);
        stmt.execute(SQL_CREATE_TABLE);
    }

    /**
     * Setup for each test, execute before each test
     * reconnect and setup default table
     */
    @Before
    public void setup() throws SQLException {
        try {
            conn = makeDefaultConnection();
            conn.setAutoCommit(true);
            for (int i = 0; i < NUM_EXTRA_THREADS; i++) {
                thread_conn[i] = makeDefaultConnection();
                thread_conn[i].setAutoCommit(true);
            }
            initDatabase();
        } catch (SQLException e) {
            DumpSQLException(e);
        }
    }

    /**
     * Cleanup for each test, execute after each test
     * drop the default table and close connection
     */
    @After
    public void teardown() throws SQLException {
        try {
            Statement stmt = conn.createStatement();
            stmt.execute(SQL_DROP_TABLE);
        } catch (SQLException e) {
            DumpSQLException(e);
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
                for (int i = 0; i < NUM_EXTRA_THREADS; i++) {
                    thread_conn[i].close();
                }
            } catch (SQLException e) {
                DumpSQLException(e);
            }
        }
    }

    /* --------------------------------------------
     * Create index tests
     * ---------------------------------------------
     */

    /**
     * Does a simple create index on a populated table
     */
    @Test
    public void testSimpleCreate() throws SQLException {
        String sql = "INSERT INTO tbl VALUES (1, 2, 100), (5, 6, 100), (3, 4, 100);";
        Statement stmt = conn.createStatement();

                int num_rows = 10000;
                System.out.println("begin insert");
                long startTime = System.currentTimeMillis();
        for (int i = 0; i < num_rows; i++) { stmt.execute(sql); }
        long elapsedTime = (new Date()).getTime() - startTime;
        System.out.println("finish insert " + elapsedTime);
        System.out.println("begin indexing");
         startTime = System.currentTimeMillis();
        stmt.execute("CREATE INDEX tbl_ind ON tbl (c2)");
         elapsedTime = (new Date()).getTime() - startTime;
        System.out.println("finish indexing " + elapsedTime);
//        ResultSet rs = stmt.executeQuery("SELECT * FROM tbl WHERE c2 > 0 ORDER BY c2 ASC");
//        rs.next();
//        checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {1, 2, 100});
//        rs.next();
//        checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {3, 4, 100});
//        rs.next();
//        checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {5, 6, 100});
//        assertNoMoreRows(rs);
    }

    /**
     * Checks to see if delete propagates to index
     */
    @Test
    public void testSimpleDelete() throws SQLException {
        String sql = "INSERT INTO tbl VALUES (1, 2, 100), (5, 6, 102);";
        Statement stmt = conn.createStatement();
        int num_rows = 500;
        for (int i = 0; i < num_rows; i++) { stmt.execute(sql); }

        // This will be the tuple that we later delete
        stmt.execute("INSERT INTO tbl VALUES (3, 4, 101);");

        stmt.execute("CREATE INDEX tbl_ind on tbl (c2);");
        ResultSet rs = stmt.executeQuery("SELECT * FROM tbl WHERE c2 > 0 ORDER BY c2 ASC;");
        for (int i = 0; i < num_rows; i++) {
            rs.next();
            checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {1, 2, 100});
        }
        rs.next();
        checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {3, 4, 101});
        for (int i = 0; i < num_rows; i++) {
            rs.next();
            checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {5, 6, 102});
        }
        assertNoMoreRows(rs);

        stmt.execute("DELETE FROM tbl WHERE c3 = 101;");
        rs = stmt.executeQuery("SELECT * FROM tbl WHERE c2 > 0 ORDER BY c2 ASC;");
        for (int i = 0; i < num_rows; i++) {
            rs.next();
            checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {1, 2, 100});
        }

        for (int i = 0; i < num_rows; i++) {
            rs.next();
            checkIntRow(rs, new String [] {"c1", "c2", "c3"}, new int [] {5, 6, 102});
        }
        assertNoMoreRows(rs);
    }

}