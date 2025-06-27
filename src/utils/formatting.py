import markdown
import markdown2
from bs4 import BeautifulSoup

def markdown_to_readable_text(md_text):
    # Convert markdown to HTML
    html = markdown2.markdown(md_text)

    # Parse the HTML
    soup = BeautifulSoup(html, "html.parser")

    # Function to format plain text from tags
    def format_text_from_html(soup):
        formatted_text = ''
        for element in soup:
            if element.name == "h1":
                formatted_text += f"\n\n# {element.text.upper()} #\n\n"
            elif element.name == "h2":
                formatted_text += f"\n\n## {element.text} ##\n\n"
            elif element.name == "h3":
                formatted_text += f"\n\n### {element.text} ###\n\n"
            elif element.name == "strong":
                formatted_text += f"**{element.text}**"
            elif element.name == "em":
                formatted_text += f"_{element.text}_"
            elif element.name == "ul":
                for li in element.find_all("li"):
                    formatted_text += f"\n - {li.text}"
            elif element.name == "ol":
                for idx, li in enumerate(element.find_all("li"), 1):
                    formatted_text += f"\n {idx}. {li.text}"
            elif element.name == "table":
                # Convert markdown table to HTML table
                formatted_text += "<table>\n"
                rows = element.find_all("tr")
                for row in rows:
                    formatted_text += "<tr>\n"
                    cols = row.find_all(["th", "td"])
                    for col in cols:
                        tag = 'th' if col.name == "th" else 'td'
                        formatted_text += f"<{tag}>{col.text.strip()}</{tag}>\n"
                    formatted_text += "</tr>\n"
                formatted_text += "</table>\n"
            else:
                formatted_text += element.text

        return formatted_text.strip()

    return format_text_from_html(soup)



def markdown_to_text(md): # og solution code 
    # Simple conversion for markdown to plain text
    md = md.replace('**', '')
    md = md.replace('*', '')
    md = md.replace('_', '')
    md = md.replace('#', '')
    md = md.replace('`', '')
    return md.strip()


def markdown_table_to_html(md_table):
    # Split the markdown table by lines
    lines = md_table.strip().split("\n")
    
    # Extract headers and rows
    headers = lines[0].strip('|').split('|')
    rows = [line.strip('|').split('|') for line in lines[2:]]  # Skip the separator line

    # Start creating the HTML table
    html_table = "<table>\n"
    
    # Add headers
    html_table += "  <thead>\n    <tr>\n"
    for header in headers:
        html_table += f"      <th>{header.strip()}</th>\n"
    html_table += "    </tr>\n  </thead>\n"
    
    # Add rows
    html_table += "  <tbody>\n"
    for row in rows:
        html_table += "    <tr>\n"
        for col in row:
            html_table += f"      <td>{col.strip()}</td>\n"
        html_table += "    </tr>\n"
    html_table += "  </tbody>\n</table>"

    return html_table

