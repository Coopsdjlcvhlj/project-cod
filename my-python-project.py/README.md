# My Python Project

## Overview
This project is a Flask application that serves as a template for building web applications in Python. It is structured to separate concerns and facilitate maintainability.

## Project Structure
```
my-python-project
├── src
│   ├── app.py                # Main entry point of the application
│   ├── __init__.py           # Marks the src directory as a package
│   ├── controllers           # Contains business logic
│   │   └── __init__.py
│   ├── routes                # Defines application routes
│   │   └── __init__.py
│   └── utils                 # Utility functions
│       └── __init__.py
├── tests                     # Contains unit tests
│   └── test_app.py
├── requirements.txt          # Lists project dependencies
├── pyproject.toml            # Project configuration
└── README.md                 # Project documentation
```

## Installation
To install the required dependencies, run the following command:

```
pip install -r requirements.txt
```

## Running the Application
To start the Flask application, navigate to the `src` directory and run:

```
python app.py
```

The application will be accessible at `http://127.0.0.1:5000`.

## Running Tests
To run the unit tests, execute:

```
pytest tests/test_app.py
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.