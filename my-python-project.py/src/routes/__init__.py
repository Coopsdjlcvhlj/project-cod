from flask import Blueprint

# Create a blueprint for the routes
routes_blueprint = Blueprint('routes', __name__)

# Import the controllers to link routes to their respective functions
from src.controllers import some_controller  # Replace with actual controller imports

# Define your routes here
@routes_blueprint.route('/example', methods=['GET'])
def example_route():
    return some_controller.example_function()  # Replace with actual function call

# You can add more routes as needed
