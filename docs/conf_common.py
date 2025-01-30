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
    "esp32p4",
    "esp32c5",
    "esp32c61",
]

# link roles config
github_repo = "espressif/esptool"

# context used by sphinx_idf_theme
html_context["github_user"] = "espressif"
html_context["github_repo"] = "esptool"

html_static_path = ["../_static"]

# Conditional content
extensions += ["esp_docs.esp_extensions.dummy_build_system"]

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
    "esp32p4": ESP32_DOCS,
    "esp32c5": ESP32_DOCS,
    "esp32c61": ESP32_DOCS,
}

# Extra options required by sphinx_idf_theme
project_slug = "esptool"

versions_url = "./_static/esptool_versions.js"
