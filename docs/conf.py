import datetime
import os

# Configuration for the Sphinx documentation builder.
# All configuration specific to your project should be done in this file.
#
# A complete list of built-in Sphinx configuration values:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
#
# The Sphinx Stack uses the Canonical Sphinx theme to keep all documentation consistent
# and on brand:
# https://github.com/canonical/canonical-sphinx

#######################
# Project information #
#######################

# Project name
project = "Notary"

# Author name; used in the default copyright statement in the page footer
author = "Canonical Group Ltd"

# The year in the copyright statement
copyright = f"{datetime.date.today().year}"

# Sidebar documentation title
html_title = project + " documentation"

# Documentation website URL
# TODO: once the ubuntu.com/docs/notary proxy is live, READTHEDOCS_CANONICAL_URL
# (set automatically by Read the Docs) will take precedence over this fallback.
ogp_site_url = os.environ.get("READTHEDOCS_CANONICAL_URL", "https://ubuntu.com/docs/notary/")

# Preview name of the documentation website
ogp_site_name = project

# Preview image URL
ogp_image = "https://assets.ubuntu.com/v1/253da317-image-document-ubuntudocs.svg"

# Product favicon; shown in bookmarks, browser tabs, etc.
html_favicon = "_static/notary-favicon.png"

# Dictionary of values to pass into the Sphinx context for all pages:
# https://www.sphinx-doc.org/en/master/usage/configuration.html#confval-html_context
html_context = {
    # Product page URL; can be different from product docs URL
    "product_page": "github.com/canonical/notary",
    # Product tag image; the orange part of your logo, shown in the page header
    "product_tag": "_static/notary-tag.png",
    # Your Discourse instance URL
    "discourse": "",
    # Your Mattermost channel URL
    "mattermost": "",
    # Your Matrix channel URL
    "matrix": "",
    # Your documentation GitHub repository URL. If set, links for viewing the
    # documentation source files and creating GitHub issues are added at the bottom of
    # each page.
    "github_url": "https://github.com/canonical/notary",
    # Docs branch in the repo; used in links for viewing the source files
    "repo_default_branch": "main",
    # Docs location in the repo; used in links for viewing the source files
    "repo_folder": "/docs/",
    # Controls the existence of Previous / Next buttons at the bottom of pages
    # Valid options: none, prev, next, both
    "sequential_nav": "both",
    # To enable listing contributors on individual pages, set to True
    "display_contributors": False,
    # Required for feedback button
    "github_issues": "enabled",
    # Passes the top-level 'author' value to the theme
    "author": author,
    # Documentation license information
    "license": {
        "name": "Apache-2.0",
        "url": "https://github.com/canonical/notary/blob/main/LICENSE",
    },
}

# Enables the "Edit this page" / "Suggest an edit" link on pages
html_theme_options = {
    "source_edit_link": "https://github.com/canonical/notary",
}

# Slug used to prefix 404 links once hosted behind the ubuntu.com/docs proxy
slug = "docs/notary"

#######################
# Sitemap configuration: https://sphinx-sitemap.readthedocs.io/
#######################

# Use RTD canonical URL to ensure duplicate pages have a specific canonical URL
html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "https://ubuntu.com/docs/notary/")

# sphinx-sitemap uses html_baseurl to generate the full URL for each page:
sitemap_url_scheme = "{link}"

# Avoids clashing with the ubuntu.com root sitemap once proxied
sitemap_filename = "doc-sitemap.xml"

# Include `lastmod` dates in the sitemap:
sitemap_show_lastmod = True

# Pages excluded from the sitemap:
sitemap_excludes = [
    "404/",
    "genindex/",
    "search/",
]

################################
# Template and asset locations #
################################

html_static_path = ["_static"]
templates_path = ["_templates"]

#############
# Redirects #
#############

# Add redirects to the 'redirects.txt' file
# https://sphinxext-rediraffe.readthedocs.io/en/latest/
rediraffe_redirects = "redirects.txt"

# Strips '/index.html' from destination URLs when building with 'dirhtml'
rediraffe_dir_only = True

###########################
# Link checker exceptions #
###########################

# A regex list of URLs that are ignored by 'make linkcheck'
linkcheck_ignore = [
    "http://127.0.0.1:8000",
    r"http://.*\.mgmt/",
]

# A regex list of URLs where anchors are ignored by 'make linkcheck'
linkcheck_anchors_ignore_for_url = [
    r"https://github\.com/.*",
    r"https://matrix\.to/.*",
]

# Give linkcheck multiple tries on failure
linkcheck_retries = 3

########################
# Configuration extras #
########################

# Custom Sphinx extensions; see
# https://www.sphinx-doc.org/en/master/usage/extensions/index.html
extensions = [
    "canonical_sphinx",
    "notfound.extension",
    "sphinx_design",
    "sphinx_rerediraffe",
    "sphinx_reredirects",
    "sphinx_tabs.tabs",
    "sphinxcontrib.jquery",
    "sphinxext.opengraph",
    "sphinx_related_links",
    "sphinx_roles",
    "sphinx_terminal",
    "sphinx_youtube_links",
    "sphinxcontrib.cairosvgconverter",
    "sphinx_last_updated_by_git",
    "sphinx_sitemap",
]

# Anchors to headings generated for MyST (Markdown) files, up to this heading level
myst_heading_anchors = 3

# Excludes files or directories from processing
exclude_patterns = [
    "doc-cheat-sheet*",
    ".venv*",
    "_dev",
]

# Adds custom CSS files, located under 'html_static_path'
html_css_files = [
    "https://assets.ubuntu.com/v1/d86746ef-cookie_banner.css",
]

# Adds custom JavaScript files, located under 'html_static_path'
html_js_files = [
    "js/overwrite_links.js",
    "https://assets.ubuntu.com/v1/287a5e8f-bundle.js",
]

# Custom content for the default 404 page
notfound_context = {
    "title": "Page not found",
    "body": "<h1>Page not found</h1>\n\n<p>Sorry, but the documentation page that you are looking for was not found.</p>\n<p>Documentation changes over time, and pages are moved around. We try to redirect you to the updated content where possible, but unfortunately, that didn't work this time (maybe because the content you were looking for does not exist in this version of the documentation).</p>\n<p>You can try to use the navigation to locate the content you're looking for, or search for a similar page.</p>\n",
}
