from esp_docs.conf_docs import *  # noqa: F403,F401

languages = ["en"]
idf_targets = [
    "esp8266",
    "esp32",
    "esp32s2",
    "esp32s3",
    "esp32c3",
    "esp32c2",
    "esp32c6",
    "esp32h2",
    "esp32h4",
    "esp32p4",
    "esp32c5",
    "esp32c61",
    "esp32h21",
]

# link roles config
github_repo = "espressif/esptool"

# context used by sphinx_idf_theme
html_context["github_user"] = "espressif"
html_context["github_repo"] = "esptool"

html_static_path = ["../_static"]

# Conditional content
extensions += [
    "esp_docs.esp_extensions.dummy_build_system",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx_tabs.tabs",
]

sphinx_tabs_disable_tab_closing = True

ESP8266_DOCS = []

ESP32_DOCS = [
    "espefuse/*",
    "espsecure/*",
]

conditional_include_dict = {
    "esp8266": ESP8266_DOCS,
    "esp32": ESP32_DOCS,
    "esp32s2": ESP32_DOCS,
    "esp32c3": ESP32_DOCS,
    "esp32s3": ESP32_DOCS,
    "esp32c2": ESP32_DOCS,
    "esp32c6": ESP32_DOCS,
    "esp32h2": ESP32_DOCS,
    "esp32h4": ESP32_DOCS,
    "esp32p4": ESP32_DOCS,
    "esp32c5": ESP32_DOCS,
    "esp32c61": ESP32_DOCS,
    "esp32h21": ESP32_DOCS,
}

# Extra options required by sphinx_idf_theme
project_slug = "esptool"

versions_url = "./_static/esptool_versions.js"


def conf_setup(app, config):
    config.html_baseurl = f"https://docs.espressif.com/projects/esptool/{config.language}/stable/{config.idf_target}/"
