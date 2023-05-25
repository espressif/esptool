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

ESP32S2_DOCS = ESP32_DOCS

ESP32C3_DOCS = ESP32S2_DOCS

ESP32S3_DOCS = ESP32S2_DOCS

ESP32C2_DOCS = ESP32S3_DOCS

ESP32C6_DOCS = ESP32C2_DOCS

ESP32H2_DOCS = ESP32C6_DOCS

conditional_include_dict = {
    "esp8266": ESP8266_DOCS,
    "esp32": ESP32_DOCS,
    "esp32s2": ESP32S2_DOCS,
    "esp32c3": ESP32C3_DOCS,
    "esp32s3": ESP32S3_DOCS,
    "esp32c2": ESP32C2_DOCS,
    "esp32c6": ESP32C6_DOCS,
    "esp32h2": ESP32H2_DOCS,
}

# Extra options required by sphinx_idf_theme
project_slug = "esptool"

versions_url = "./_static/esptool_versions.js"
