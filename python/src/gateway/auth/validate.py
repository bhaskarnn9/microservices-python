import os
import requests


def token(request):
    if 'Authorization' not in request.headers:
        return None, ('Missing credentials', 401)

    tk = request.headers['Authorization']

    if not tk:
        return None, ('Missing credentials', 401)

    response = requests.post(
        f"http://{os.environ.get('AUTH_SVC_ADDRESS')}/validate",
        headers={'Authorization': tk}
    )

    if response.status_code == 200:
        return response.text, None
    else:
        None, (response.text, response.status_code)
