def get_owasp_categories_section(
    owasp_counts,
    owasp_drilldown_pages,
):
    category_items = ""

    sorted_categories = sorted(
        owasp_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for owasp, count in sorted_categories:
        page_path = owasp_drilldown_pages.get(owasp)

        if page_path:
            category_items += f"""
            <a class="owasp-category-card" href="{page_path}">
                <strong>{owasp}</strong>
                <span>{count} findings</span>
            </a>
            """
        else:
            category_items += f"""
            <div class="owasp-category-card">
                <strong>{owasp}</strong>
                <span>{count} findings</span>
            </div>
            """

    return f"""
<h2>OWASP Categories</h2>

<div class="owasp-category-grid">
    {category_items}
</div>
"""