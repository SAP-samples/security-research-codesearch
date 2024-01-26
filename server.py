import os
from pathlib import Path

from flask import Flask, render_template, request, Response

from src.database import Database

os.environ["TOKENIZERS_PARALLELISM"] = "true"
app = Flask(__name__, static_url_path="/static", static_folder='templates/lib/')
# app.logger.setLevel("INFO")

app.logger.info("Starting database")
database = Database(size=256, has_pca=False, statement_hashes=True)
database.load_database_from_folder("data/libxml2vuln/")
app.logger.info("Database loaded")

ids = 0

DEFAULT_PATH = "/Path/to/codebase/"
pathtocodebase = DEFAULT_PATH

RESULT_TEMPLATE = """
        <div class='result'>
            <div class='found'> {} {} </div>
                <pre><code class='language-c' id={}> {}</code></pre>
            </div>
        </div>
"""

VULN_RESULT_TEMPLATE = """
        <div class='result'>
            <div class='found'> {} {} {} </div>
                <pre><code class='language-c' id={}> {}</code></pre>
            </div>
        </div>
"""

RELOAD_HIGHLIGHT = "<script>hljs.highlightAll();</script>"


@app.route("/search", methods=["POST"])
def search():
    global ids
    query = request.form["query"]
#    try:
    results = database.query(query)

    output = ""
    for result in results:
        parsed = database.locality_to_code(
            result["locality"],
            result["location"],
            pathtocodebase)
        if len(parsed) < 5:
            continue
        output += RESULT_TEMPLATE.format(
            result['location'],
            result['score'],
            ids,
            parsed)
        ids += 1
    output += RELOAD_HIGHLIGHT
    return Response(output, "200")


#    except Exception as e:
#        app.logger.error(e)
#        return Response("<div class='result'>No DB initialized</div>", "200")


@app.route("/vuln", methods=["POST"])
def vuln():
    global ids
    try:
        results = database.check_for_vulns("data/vuln_queries_functions.pkl")

        output = ""
        for result in results:
            cwes = " ".join(result["desc"])
            if len(cwes) < 3:
                continue
            parsed = database.locality_to_code(
                result["locality"],
                result["location"],
                pathtocodebase)
            if len(parsed) < 5:
                continue
            output += VULN_RESULT_TEMPLATE.format(
                cwes,
                result['location'],
                result['score'],
                ids,
                parsed)
            ids += 1
            ids += 1
        output += RELOAD_HIGHLIGHT
        return Response(output, "200")
    except Exception as e:
        app.logger.error(e)
        return Response("<div class='result'>No DB initialized</div>", "200")


@app.route("/upload", methods=["POST"])
def upload():
    global pathtocodebase
    path = request.form["path"]
    database.build_database(path)
    database.load_database_from_folder(Path("data/dataset/"))
    pathtocodebase = path
    return Response(
        "<div class='loading'><div class='result'>Please wait while the database is initialized</div></div>", "200")


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


if __name__ == "__main__":
    app.run()
