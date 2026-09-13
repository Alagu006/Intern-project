import pytest
from flask import Flask, request
from app.utils import get_pagination_params, paginate_query, _get_pagination_params, _paginate_query
from app.extensions import db
from app.models import User


class TestPaginationUtils:
    """Tests for shared pagination helpers in app/utils.py."""

    def test_pagination_params_defaults(self):
        app = Flask(__name__)
        with app.test_request_context("/?page=1"):
            page, per_page = get_pagination_params()
            assert page == 1
            assert per_page == 20

    def test_pagination_params_custom_query_args(self):
        app = Flask(__name__)
        with app.test_request_context("/?page=3&per_page=50"):
            page, per_page = get_pagination_params()
            assert page == 3
            assert per_page == 50

    def test_pagination_params_max_per_page_capping(self):
        app = Flask(__name__)
        with app.test_request_context("/?per_page=500"):
            page, per_page = get_pagination_params()
            assert per_page == 100

    def test_pagination_params_invalid_and_negative_values(self):
        app = Flask(__name__)
        with app.test_request_context("/?page=-5&per_page=invalid"):
            page, per_page = get_pagination_params()
            assert page == 1
            assert per_page == 20

    def test_paginate_query_function(self, app):
        with app.app_context():
            result = paginate_query(User.query, 1, 10)
            assert "items" in result
            assert "total" in result
            assert "page" in result
            assert "per_page" in result
            assert "pages" in result
            assert result["page"] == 1
            assert result["per_page"] == 10
