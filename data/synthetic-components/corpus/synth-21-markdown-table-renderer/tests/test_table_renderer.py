from custom_components.markdown_table_renderer import MarkdownTableRenderer
from custom_components.markdown_table_renderer.markdown_escape import escape_cell
def test_table_shape():
    renderer = MarkdownTableRenderer(columns=["name"])
    markdown = renderer.run(rows=[{"name": "alpha"}])["markdown"]
    assert markdown.splitlines()[0] == "| name |"
    assert markdown.splitlines()[-1] == "| alpha |"
