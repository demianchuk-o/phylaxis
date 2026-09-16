"""A second module, so the packed sdist has more than a couple of entries."""


def slugify(text):
    return "-".join(text.lower().split())
