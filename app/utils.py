"""
Shared application utilities and pagination helpers.
"""

from flask import request


def get_pagination_params(default_page=1, default_per_page=20, max_per_page=100):
    """
    Extract and validate pagination parameters from request.args.

    Returns:
        tuple[int, int]: (page, per_page)
        - page: >= 1 (defaults to default_page)
        - per_page: clamped between 1 and max_per_page (defaults to default_per_page)
    """
    raw_page = request.args.get("page", default_page, type=int)
    raw_per_page = request.args.get("per_page", default_per_page, type=int)

    page = max(1, raw_page if raw_page is not None else default_page)
    per_page = max(
        1,
        min(
            raw_per_page if raw_per_page is not None else default_per_page,
            max_per_page,
        ),
    )
    return page, per_page


def paginate_query(query, page, per_page):
    """
    Apply pagination to an SQLAlchemy query and return a dict with items and pagination metadata.

    Returns:
        dict: {
            "items": list,
            "total": int,
            "page": int,
            "per_page": int,
            "pages": int,
        }
    """
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return {
        "items": [item for item in pagination.items],
        "total": pagination.total,
        "page": page,
        "per_page": per_page,
        "pages": pagination.pages,
    }


# Aliases matching private helper naming for backward compatibility
_get_pagination_params = get_pagination_params
_paginate_query = paginate_query
