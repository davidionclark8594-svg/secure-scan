import html


def get_cwe_categories_section(
    cwe_counts,
    cwe_drilldown_pages,
):
    category_items = ""

    sorted_categories = sorted(
        cwe_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for cwe, count in sorted_categories:
        page_path = cwe_drilldown_pages.get(cwe)
        safe_cwe = html.escape(str(cwe))

        if page_path:
            category_items += f"""
            <a
                class="owasp-category-card"
                href="{page_path}"
            >
                <strong>{safe_cwe}</strong>
                <span>{count} findings</span>
            </a>
            """
        else:
            category_items += f"""
            <div class="owasp-category-card">
                <strong>{safe_cwe}</strong>
                <span>{count} findings</span>
            </div>
            """

    return f"""
<h2>CWE Weakness Categories</h2>

<div class="owasp-category-grid">
    {category_items}
</div>
"""