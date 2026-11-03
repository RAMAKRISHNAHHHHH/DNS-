from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3, csv, io, os
from detector.detector import analyze_dns_query

app = Flask(__name__)
app.secret_key = "dns-tunnel-demo-key"
DB = os.path.join("database", "dns.db")

def init_db():
    os.makedirs("database", exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src_ip TEXT, query TEXT, record_type TEXT,
        query_length INTEGER, entropy REAL, risk TEXT, reason TEXT
    )""")
    con.commit(); con.close()

def rows():
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
    data = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    con.close(); return data

@app.route("/")
def dashboard():
    data = rows()
    total = len(data)
    high = sum(x["risk"] == "HIGH" for x in data)
    medium = sum(x["risk"] == "MEDIUM" for x in data)
    normal = sum(x["risk"] == "NORMAL" for x in data)
    return render_template("dashboard.html", alerts=data, total=total, high=high, medium=medium, normal=normal)

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".csv"):
        flash("Please upload a CSV file.")
        return redirect(url_for("dashboard"))
    con = sqlite3.connect(DB)
    reader = csv.DictReader(io.TextIOWrapper(f.stream, encoding="utf-8-sig"))
    count = 0
    for r in reader:
        query = (r.get("query") or r.get("domain") or "").strip()
        if not query: continue
        src = r.get("src_ip") or r.get("source_ip") or "Unknown"
        ts = r.get("timestamp") or ""
        typ = r.get("record_type") or r.get("type") or "A"
        result = analyze_dns_query(query, typ)
        con.execute("""INSERT INTO alerts(timestamp,src_ip,query,record_type,query_length,entropy,risk,reason)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (ts, src, query, typ, result["length"], result["entropy"],
                     result["risk"], result["reason"]))
        count += 1
    con.commit(); con.close()
    flash(f"Analyzed {count} DNS queries.")
    return redirect(url_for("dashboard"))

@app.route("/clear", methods=["POST"])
def clear():
    con = sqlite3.connect(DB); con.execute("DELETE FROM alerts"); con.commit(); con.close()
    flash("Dashboard data cleared.")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
