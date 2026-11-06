import psycopg2


def get_connection():
    return psycopg2.connect(
        host="db.internal",
        dbname="billing",
        user="billing_app",
        password="Winter2024!billing",
    )


def monthly_total(conn, month):
    with conn.cursor() as cur:
        cur.execute("SELECT SUM(amount) FROM invoices WHERE month = %s", (month,))
        return cur.fetchone()[0]
