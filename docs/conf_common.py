from esp_docs.conf_docs import *  # noqa: F403,F401

languages = ['en']
idf_targets = ['esp8266', 'esp32', 'esp32s2', 'esp32s3', 'esp32c3']

# link roles config
github_repo = 'espressif/esptool'

# context used by sphinx_idf_theme
html_context['github_user'] = 'espressif'
html_context['github_repo'] = 'esptool'

html_static_path = ['../_static']

# Extra options required by sphinx_idf_theme
project_slug = 'esptool'

versions_url = './_static/esptool_versions.js'
