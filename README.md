# SAP Security Research - Fuzzy Code Search Tool

[![REUSE status](https://api.reuse.software/badge/github.com/SAP-samples/security-research-codesearch)](https://api.reuse.software/info/github.com/SAP-samples/security-research-codesearch)

## Description

This tool leverages

 - FAISS,
 - C/C++ Parser Lizzard,
 - and CodeT5+
 
for **natural language** and **code similarity** search.

## Requirements
(see `requirements.txt`)

 - torch
 - transformers
 - tqdm
 - numpy
 - scikit-learn
 - sentence-transformers
 - flask
 - torchvision
 - torchaudio
 - sctokenizer
 - faiss-cpu
 - umap-learn
 - lizard
 - optimum
 - pathlib

## Fuzzy Code Search

Vector representations of the functions in **your project** is loaded into the FAISS vector database.

Run the script `server.py` and connect to `localhost:5000` (resp. `127.0.0.1:5000`).

### Upload Dataset

(cf. method `load_database_from_folder` in `database.py`)

Scan a local directory for `.c` or `.cpp` files, encode them with CodeT5+ and load them into the vector database.

### Search Button

(cf. method `query` in `database.py`)

*Prerequisite: having uploaded your project.*

 - Find code similar to given sample code put into the text box (e.g. duplicates of known/found bugs) 
 - Find code that matches a textual description in the input field.


### Vulnerability Search

(cf. method check_for_vulns in database.py)

Search for examples from a (fixed) list of known vulnerable functions ("data/vuln_queries_functions.pkl") inside the uploaded project.


## Vulnerable Code Clone Detection

A **dataset consisting of vulnerable samples** (taken from DiverseVul) is loaded into the FAISS vector database.

Run the script `server2.py` and connect to `localhost:5000` (resp. `127.0.0.1:5000`).

Write some code in the search field. Then similar code to the input is searched for in the database of vulnerable samples.

### Search Button

(cf. method index_query in database.py)

lookup some code (text box) in the database of vulnerable samples and display CWE-Info. 

## Known Issues

No known issues.

## How to obtain support
[Create an issue](https://github.com/SAP-samples/<repository-name>/issues) in this repository if you find a bug or have questions about the content.
 
For additional support, [ask a question in SAP Community](https://answers.sap.com/questions/ask.html).

## Contributing
If you wish to contribute code, offer fixes or improvements, please send a pull request. Due to legal reasons, contributors will be asked to accept a DCO when they create the first pull request to this project. This happens in an automated fashion during the submission process. SAP uses [the standard DCO text of the Linux Foundation](https://developercertificate.org/).

## License
Copyright (c) 2024 SAP SE or an SAP affiliate company. All rights reserved. This project is licensed under the Apache Software License, version 2.0 except as noted otherwise in the [LICENSE](LICENSE) file.
