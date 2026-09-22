import sys
import time
import json

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from src.db_mcp.database import initialize_database, DB_PATH, ALLOWED_BUSINESS_TABLES
from src.db_mcp.guardrails.ast_guard import validate_and_transform_query, ASTGuardrailError
from src.db_mcp.guardrails.executor import execute_bounded_query
from src.db_mcp.server import safe_query, propose_mutation, apply_mutation


def run_benchmark_timing():
    print("\n" + "=" * 80)
    print(" [BENCHMARK] HIGH-RESOLUTION LATENCY PROFILING (100 Iterations)")
    print("=" * 80)

    test_queries = [
        ("Point Query", "SELECT * FROM products WHERE id = 42"),
        ("Aggregation Query", "SELECT category, count(*), avg(price) FROM products GROUP BY category"),
        ("Multi-Table Join", "SELECT o.id, c.name, o.total_amount FROM orders o JOIN customers c ON o.customer_id = c.id LIMIT 50"),
    ]

    for label, sql in test_queries:
        ast_times = []
        db_times = []
        mask_times = []
        total_times = []

        # Warm up 5 runs
        for _ in range(5):
            safe_sql, _ = validate_and_transform_query(sql, ALLOWED_BUSINESS_TABLES)
            execute_bounded_query(safe_sql, db_path=DB_PATH)

        # 100 measurement runs
        for _ in range(100):
            t0 = time.perf_counter()
            safe_sql, _ = validate_and_transform_query(sql, ALLOWED_BUSINESS_TABLES)
            t1 = time.perf_counter()
            res = execute_bounded_query(safe_sql, db_path=DB_PATH)
            t2 = time.perf_counter()

            ast_times.append((t1 - t0) * 1000)
            db_times.append((t2 - t1) * 1000)
            total_times.append((t2 - t0) * 1000)

        avg_ast = sum(ast_times) / len(ast_times)
        avg_db = sum(db_times) / len(db_times)
        avg_total = sum(total_times) / len(total_times)
        p95_total = sorted(total_times)[int(len(total_times) * 0.95)]

        print(f"\n  Query: [{label}]")
        print(f"  SQL:   \"{sql}\"")
        print(f"  ├── AST Parse & Rewrite : {avg_ast:.3f} ms")
        print(f"  ├── DB Execution + Stream: {avg_db:.3f} ms")
        print(f"  ├── Average E2E Latency : {avg_total:.3f} ms")
        print(f"  └── P95 E2E Latency     : {p95_total:.3f} ms")


def run_attack_simulations():
    print("\n" + "=" * 80)
    print(" 🛡️ ATTACK SIMULATION & GUARDRAIL DEMONSTRATION")
    print("=" * 80)

    attacks = [
        (
            "Attack 1: Multi-Statement Semicolon Injection",
            "SELECT * FROM products; DROP TABLE customers;",
            "Attacker attempts to stack a destructive statement."
        ),
        (
            "Attack 2: Subquery Camouflage on Restricted Table",
            "SELECT * FROM (SELECT * FROM admin_tokens) AS leak",
            "Attacker hides restricted 'admin_tokens' table inside a nested subquery."
        ),
        (
            "Attack 3: Common Table Expression (CTE) Bypass",
            "WITH payroll AS (SELECT * FROM salaries) SELECT * FROM payroll",
            "Attacker wraps confidential 'salaries' table inside a WITH clause."
        ),
        (
            "Attack 4: Autonomous Write / Mutation Attempt",
            "DELETE FROM orders WHERE id = 10",
            "Attacker attempts to delete business orders in autonomous read-only mode."
        ),
        (
            "Attack 5: Runaway Cartesian Aggregation (Denial of Service)",
            "SELECT count(*) FROM products, products, products, products, products",
            "Attacker forces 10B row Cartesian scan to lock CPU/database."
        ),
        (
            "Attack 6: Unbounded LIMIT Blowup (Context Poisoning)",
            "SELECT * FROM products LIMIT 9999999",
            "Attacker requests 10M rows to overflow LLM context window."
        ),
    ]

    for title, attack_sql, note in attacks:
        print(f"\n▶ {title}")
        print(f"  Note: {note}")
        print(f"  Input SQL: \"{attack_sql}\"")

        t0 = time.perf_counter()
        response_raw = safe_query(attack_sql)
        elapsed = (time.perf_counter() - t0) * 1000
        res = json.loads(response_raw)

        status = res.get("status")
        if status == "REJECTED_BY_GUARDRAIL":
            print(f"  Result: 🛑 BLOCKED BY AST GUARDRAIL (Latency: {elapsed:.2f} ms)")
            print(f"  Reason: {res.get('error')}")
        elif status == "EXECUTION_TIMEOUT":
            print(f"  Result: ⏱️ TERMINATED BY TIMEOUT (Latency: {elapsed:.2f} ms)")
            print(f"  Reason: {res.get('error')}")
        elif status == "SUCCESS":
            # For LIMIT clamping
            print(f"  Result: 🔒 MUTATED & BOUNDED SAFELY (Latency: {elapsed:.2f} ms)")
            print(f"  Safe Rewritten SQL: {res.get('executed_safe_sql')}")
            print(f"  Rows Returned: {res.get('row_count')}")


def run_hitl_demo():
    print("\n" + "=" * 80)
    print(" 🤝 HUMAN-IN-THE-LOOP (HITL) WORKFLOW DEMONSTRATION")
    print("=" * 80)

    # Step 1: Propose mutation
    mutation_sql = "UPDATE products SET price = 12.99 WHERE id = 5"
    print(f"\nStep 1: Agent requests data mutation: \"{mutation_sql}\"")
    prop_raw = propose_mutation(mutation_sql)
    prop = json.loads(prop_raw)
    token = prop["proposal"]["proposal_token"]
    print(f"  ├── Status: {prop['status']}")
    print(f"  ├── Statement Type: {prop['proposal']['statement_type']}")
    print(f"  ├── Target Tables: {prop['proposal']['target_tables']}")
    print(f"  └── Proposal Token: {token}")

    # Step 2: Unapproved execution attempt
    print("\nStep 2: Attempting execution WITHOUT human approval (human_approved=False)...")
    reject_raw = apply_mutation(token, human_approved=False)
    print(f"  └── Result: {json.loads(reject_raw)['status']} - Rejected as expected.")

    # Step 3: Approved execution
    print("\nStep 3: Human reviews and explicitly confirms (human_approved=True)...")
    accept_raw = apply_mutation(token, human_approved=True)
    accept = json.loads(accept_raw)
    print(f"  ├── Status: {accept['status']}")
    print(f"  ├── Affected Rows: {accept['affected_rows']}")
    print(f"  └── Execution Time: {accept['execution_time_ms']} ms")


def main():
    print("Initializing Database...")
    initialize_database(DB_PATH)
    run_benchmark_timing()
    run_attack_simulations()
    run_hitl_demo()
    print("\n" + "=" * 80)
    print(" ✅ ALL DEMONSTRATIONS AND BENCHMARKS COMPLETE")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
