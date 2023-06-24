# Testing setup
Install development requirements from the root directory:
```
python -m pip install dev-requirements.txt
```

# Running unit tests
Run the following from the `tests/` folder:
```
python -m unittest discover .
```
Determine coverage:
```
python -m coverage run -m unittest discover .
python -m coverage html
```

# User testing
Run the test server:
```
python tests/test_server.py
```
Run a test request in `asdfuzz`:
```
python -m asdfuzz --filename tests/get_request.txt --no-https
```
