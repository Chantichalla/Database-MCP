"""
Automated Test Suite for Safe Database MCP Gateway.
Verifies all 6 attack vectors, AST parsing, table whitelisting, bounded execution,
memory limits, PII masking, and Human-in-the-Loop mutation workflows.
"""
import os
import json
import unittest
import tempfile
import sqlite3

from src.database_gateway.database import initialize_database, ALLOWED_BUSINESS_TABLES
from src.database_gateway.guardrails.ast_guard import (
    validate_and_transform_query,
    inspect_mutation_ast,
    ASTGuardrailError
)
from src.database_gateway.guardrails.executor import execute_bounded_query
from src.database_gateway.server import (
    safe_query,
    list_accessible_tables,
    describe_table,
    propose_mutation,
    apply_mutation
)


class TestDatabaseGateway(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.temp_db.close()
        initialize_database(cls.temp_db.name)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.temp_db.name):
            try:
                os.remove(cls.temp_db.name)
            except OSError:
                pass

    # =========================================================================
    # 1. AST PARSING TESTS (Not Regex Safety)
    # =========================================================================

    def test_multistatement_injection_rejected(self):
        """Attacker tries to chain a malicious statement via semicolon."""
        attack_sql = "SELECT * FROM products; DROP TABLE products;"
        with self.assertRaises(ASTGuardrailError) as ctx:
            validate_and_transform_query(attack_sql, ALLOWED_BUSINESS_TABLES)
        self.assertIn("Multi-statement query detected", str(ctx.exception))

    def test_sql_comment_evasion_handled_cleanly(self):
        """Attacker uses SQL comments to evade naive regex filters."""
        # Comments should be transparently parsed by AST without breaking
        query = "SELECT/**/id,/**/name/**/FROM/**/products/**/WHERE/**/price > 50"
        safe_sql, tables = validate_and_transform_query(query, ALLOWED_BUSINESS_TABLES)
        self.assertIn("products", tables)
        self.assertIn("LIMIT", safe_sql.upper())

    def test_subquery_table_bypass_rejected(self):
        """Attacker tries to query restricted 'salaries' table inside a subquery."""
        subquery_attack = "SELECT * FROM (SELECT * FROM salaries) AS hidden_salaries"
        with self.assertRaises(ASTGuardrailError) as ctx:
            validate_and_transform_query(subquery_attack, ALLOWED_BUSINESS_TABLES)
        self.assertIn("salaries", str(ctx.exception).lower())

    def test_cte_table_bypass_rejected(self):
        """Attacker hides restricted 'admin_tokens' table inside a Common Table Expression (WITH clause)."""
        cte_attack = "WITH leaked_creds AS (SELECT * FROM admin_tokens) SELECT * FROM leaked_creds"
        with self.assertRaises(ASTGuardrailError) as ctx:
            validate_and_transform_query(cte_attack, ALLOWED_BUSINESS_TABLES)
        self.assertIn("admin_tokens", str(ctx.exception).lower())

    def test_autonomous_mutation_rejected(self):
        """Autonomous query tool must reject DELETE/UPDATE/DROP/INSERT."""
        disallowed_queries = [
            "DELETE FROM orders WHERE id = 1",
            "UPDATE products SET price = 0.99 WHERE id = 1",
            "DROP TABLE customers",
            "INSERT INTO products (name, category, price, stock_quantity) VALUES ('x', 'y', 1.0, 10)",
        ]
        for query in disallowed_queries:
            with self.assertRaises(ASTGuardrailError) as ctx:
                validate_and_transform_query(query, ALLOWED_BUSINESS_TABLES)
            self.assertIn("Autonomous execution permits only 'SELECT'", str(ctx.exception))

    # =========================================================================
    # 2. AST LIMIT CLAMPING & MEMORY PROTECTION TESTS
    # =========================================================================

    def test_unbounded_select_limit_injected(self):
        """If user writes SELECT * FROM products with no LIMIT, AST must inject LIMIT 100."""
        raw_sql = "SELECT * FROM products"
        safe_sql, _ = validate_and_transform_query(raw_sql, ALLOWED_BUSINESS_TABLES, max_limit=100)
        self.assertTrue(safe_sql.upper().endswith("LIMIT 100") or "LIMIT 100" in safe_sql.upper())

    def test_excessive_limit_clamped(self):
        """If user requests LIMIT 50000, AST must clamp it to max_limit (100)."""
        raw_sql = "SELECT * FROM products LIMIT 50000"
        safe_sql, _ = validate_and_transform_query(raw_sql, ALLOWED_BUSINESS_TABLES, max_limit=100)
        self.assertIn("LIMIT 100", safe_sql.upper())
        self.assertNotIn("50000", safe_sql)

    # =========================================================================
    # 3. BOUNDED EXECUTION, TIMEOUT, & PII PROTECTION TESTS
    # =========================================================================

    def test_runaway_cartesian_query_timeout(self):
        """Runaway query with 4-way unindexed Cartesian join must be killed by timeout handler."""
        # 100 * 100 * 100 * 100 = 100,000,000 Cartesian product rows
        heavy_query = "SELECT count(*) FROM products, products, products, products"
        with self.assertRaises(TimeoutError) as ctx:
            execute_bounded_query(heavy_query, db_path=self.temp_db.name, timeout_seconds=0.5)
        self.assertIn("exceeded execution deadline", str(ctx.exception).lower())

    def test_pii_masking_applied(self):
        """Customer emails and phone numbers must be dynamically masked."""
        query = "SELECT name, email, phone FROM customers LIMIT 5"
        result = execute_bounded_query(query, db_path=self.temp_db.name, mask_pii=True)
        self.assertGreater(result["row_count"], 0)
        for row in result["rows"]:
            # Check email masking (e.g. c***1@example.com)
            self.assertIn("***", row["email"])
            self.assertTrue(row["email"].endswith("@example.com"))
            # Check phone masking (e.g. ***-***-0101)
            self.assertTrue(row["phone"].startswith("***-***-"))

    # =========================================================================
    # 4. MCP TOOL SURFACE & HITL MUTATION TESTS
    # =========================================================================

    def test_mcp_safe_query_success(self):
        """Verifies end-to-end safe_query execution through the MCP tool."""
        res_json = safe_query("SELECT id, name, price FROM products WHERE price < 30")
        res = json.loads(res_json)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreater(res["row_count"], 0)
        self.assertEqual(res["tables_accessed"], ["products"])

    def test_mcp_safe_query_rejects_restricted_table(self):
        """Verifies safe_query properly returns structured rejection for restricted table."""
        res_json = safe_query("SELECT * FROM salaries")
        res = json.loads(res_json)
        self.assertEqual(res["status"], "REJECTED_BY_GUARDRAIL")
        self.assertIn("salaries", res["error"].lower())

    def test_hitl_mutation_lifecycle(self):
        """
        Tests the 2-step Human-in-the-Loop mutation flow:
        Step 1: Propose mutation -> Returns token and query plan.
        Step 2: Apply mutation with human approval -> Executes and modifies DB.
        """
        mutation_sql = "UPDATE products SET price = 25.50 WHERE id = 1"
        prop_json = propose_mutation(mutation_sql)
        prop_res = json.loads(prop_json)

        self.assertEqual(prop_res["status"], "PROPOSAL_CREATED")
        token = prop_res["proposal"]["proposal_token"]
        self.assertTrue(token.startswith("prop_"))

        # Try to apply without approval -> Must abort
        aborted_json = apply_mutation(token, human_approved=False)
        self.assertEqual(json.loads(aborted_json)["status"], "MUTATION_ABORTED")

        # Apply with human approval -> Must succeed
        success_json = apply_mutation(token, human_approved=True)
        success_res = json.loads(success_json)
        self.assertEqual(success_res["status"], "SUCCESS")
        self.assertEqual(success_res["affected_rows"], 1)

        # Token should now be invalidated (replay attack prevention)
        replay_json = apply_mutation(token, human_approved=True)
        self.assertEqual(json.loads(replay_json)["status"], "INVALID_TOKEN")

    def test_hitl_mutation_rejects_unconstrained_update(self):
        """Proposing an UPDATE without a WHERE clause must be rejected by guardrail."""
        dangerous_sql = "UPDATE products SET price = 0.0"
        prop_json = propose_mutation(dangerous_sql)
        prop_res = json.loads(prop_json)
        self.assertEqual(prop_res["status"], "REJECTED_BY_GUARDRAIL")
        self.assertIn("without a WHERE clause is prohibited", prop_res["error"])


if __name__ == "__main__":
    unittest.main()
