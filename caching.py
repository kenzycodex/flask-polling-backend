from flask import Blueprint, jsonify, current_app
from flask_caching import Cache

cache_blueprint = Blueprint('cache', __name__)

# Configure Flask-Caching
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})

@cache_blueprint.before_app_request
def setup_cache():
    cache.init_app(current_app)  # Initialize the cache with the current app

@cache_blueprint.route('/poll/<int:poll_id>')
@cache.cached(timeout=60)  # Cache this route for 60 seconds
def cached_poll_results(poll_id):
    poll = next((p for p in polls if p['id'] == poll_id), None)
    if poll:
        return jsonify({"poll": poll}), 200
    return jsonify({"error": "Poll not found"}), 404