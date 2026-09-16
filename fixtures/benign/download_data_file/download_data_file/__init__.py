"""PHX-DRP-001 negative: a network response that is parsed as data, never executed.

The response reaches csv.reader, which is not a CodeExecution sink. Fetching a dataset is
ordinary; handing the body to exec is not.
"""
import csv
import io
import urllib.request

DATA_URL = "https://data.example.invalid/rates.csv"


def load_rates():
    body = urllib.request.urlopen(DATA_URL).read().decode("utf-8")
    return list(csv.reader(io.StringIO(body)))
