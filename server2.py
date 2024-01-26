from glob import glob

from flask import Flask, render_template, request, Response
from tqdm import tqdm

from src.database import Database

app = Flask(__name__, static_url_path="/static", static_folder='templates/lib/')

database = Database(size=256, has_pca=False, statement_hashes=False, context_hashes=False)
database.load_database_from_folder("data/vuln_dataset/")
ids = 0

RESULT_TEMPLATE = """
        <div class='result'>
            <div class='found'> {} {} Line {} to {} <br> Similar to {} </div>
        </div>
"""

RELOAD_HIGHLIGHT = "<script>hljs.highlightAll();</script>"


@app.route("/search", methods=["POST"])
def search():
    global ids
    query = request.form["query"]
    try:
        D, I, statements, cves = database.index_query(query)

        output = ""
        relevant_line = 0
        score = 0
        cwe = "N/A"
        cve = "N/A"

        maxDStatement = -10000
        maxDFunction = -10000
        print(D, I, statements, cves)

        for i, _ in enumerate(D):
            if D[i] <= 0.9 or I[i] == 0:
                continue

            # First Get the highest scoring Statement/Line Level Information
            if i < statements and D[i] >= maxDStatement:
                relevant_line = (i + 1) * 5
                score = D[i]
                cwe = I[i]
                maxDStatement = D[i]

                # The CVE information seems to be best taken from the statement level. It fits more often
                cve = cves[i]

            # Second and if present, get the most relevant Function Level CWE
            if i >= statements and D[i] >= maxDFunction:
                score = D[i]
                cwe = I[i]
                maxDFunction = D[i]

        output += RESULT_TEMPLATE.format(
            cwe,
            score,
            relevant_line,
            relevant_line + 5,
            cve)
        output += RELOAD_HIGHLIGHT
        return Response(output, "200")


    except Exception as e:
        app.logger.error(e)
        return Response("<div class='result'>No DB initialized</div>", "200")


def eval():
    TP = 0
    FP = 0
    TN = 0
    FN = 0
    for pos in tqdm(glob("/Users/i534627/Projects/codeartifactevaluation/dataset/original/*_1.c")[:1000]):
        try:
            D, I, statements, cves = database.index_query(open(pos, "r").read())
            if D[0] > 0.999:
                TP += 1
            else:
                FN += 1
        except Exception:
            continue
    for pos in tqdm(glob("/Users/i534627/Projects/codeartifactevaluation/dataset/original/*_0.c")[:1000]):
        try:
            D, I, statements, cves = database.index_query(open(pos, "r").read())
            if D[0] > 0.999:
                FP += 1
            else:
                TN += 1
        except Exception:
            continue

    print("TPs: {}, FPs: {}, TNs: {}, FNs: {}".format(TP, FP, TN, FN))


@app.route("/", methods=["GET"])
def home():
    return render_template("index2.html")


if __name__ == "__main__":
    #eval()
    app.run()
